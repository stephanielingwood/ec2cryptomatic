#!/usr/bin/env python3
# coding: utf-8

import argparse
import boto3
import logging
import sys
from concurrent.futures.thread import ThreadPoolExecutor
from botocore.exceptions import ClientError
from botocore.exceptions import EndpointConnectionError

# Define the global logger

logger = logging.getLogger('ec2-cryptomatic')
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s %(threadName)s : %(message)s')
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)
stream_handler.setLevel(logging.DEBUG)
logger.addHandler(stream_handler)


class EC2Cryptomatic(object):
    """ Encrypt EBS volumes from an EC2 instance """

    def __init__(self, region: str, instance: str, key: str):
        """ Constructor
            :param region: the AWS region where the instance is
            :param instance: one instance-id
            :param key: the AWS KMS Key to be used to encrypt the volume
        """
        self._logger = logging.getLogger('ec2-cryptomatic')
        self._logger.setLevel(logging.DEBUG)
        self._kms_key = key

        self._ec2_client = boto3.client('ec2', region_name=region)
        self._ec2_resource = boto3.resource('ec2', region_name=region)
        self._region = region
        self._instance = self._ec2_resource.Instance(id=instance)

        # Waiters
        self._wait_snapshot = self._ec2_client.get_waiter('snapshot_completed')
        self._wait_volume = self._ec2_client.get_waiter('volume_available')

        # Sets the timeout period for waiters to 20 minutes
        # Waiter will poll every 15s for 80 cycles (20 minutes)
        self._wait_snapshot.config.max_attempts = 80
        self._wait_volume.config.max_attempts = 80

        # Do some pre-check : instances must exist and be stopped
        self._instance_is_exists()
        self._instance_is_stopped()

    def _instance_is_exists(self):
        try:
            self._ec2_client.describe_instances(
                InstanceIds=[self._instance.id])
        except ClientError:
            raise

    def _instance_is_stopped(self):
        if self._instance.state['Name'] != 'stopped':
            raise TypeError('Instance still running ! please stop it.')

    def _start_instance(self):
        try:
            self._logger.info('-> Starting instance %s' % self._instance.id)
            self._ec2_client.start_instances(InstanceIds=[self._instance.id])
            self._logger.info('-> Instance %s started' % self._instance.id)
        except ClientError:
            raise

    def _cleanup(self, device, discard_source, snapshot, encrypted):
        """ Delete the temporary objects
            :param device: the original device to delete
        """

        self._logger.info('->Cleanup of resources')
        self._wait_volume.wait(VolumeIds=[device.id])

        if discard_source:
            self._logger.info('-->Deleting unencrypted volume %s' % device.id)
            device.delete()

        else:
            self._logger.info(
                '-->Preserving unencrypted volume %s' % device.id)

        snapshot.delete()
        encrypted.delete()

    def _create_volume(self, encrypted_snapshot, original_device):
        """ Create an encrypted volume from an encrypted snapshot
            :param encrypted_snapshot: an encrypted snapshot
            :param original_device: device where take additional informations
        """

        self._logger.info(
            '->Creating an encrypted volume from %s' % encrypted_snapshot.id)

        tag_list = []

        if original_device.tags:
            # don't copy aws reserved tags
            tag_list = list(filter(
                lambda tag: not tag['Key'].startswith('aws:'), original_device.tags))

        volume = self._ec2_resource.create_volume(
            SnapshotId=encrypted_snapshot.id,
            VolumeType=original_device.volume_type,
            AvailabilityZone=original_device.availability_zone,
            TagSpecifications=[{'ResourceType': 'volume', 'Tags': tag_list}])
        self._wait_volume.wait(VolumeIds=[volume.id])

        return volume

    def _encrypt_snapshot(self, snapshot, device):
        """ Copy and encrypt a snapshot
            :param snapshot: snapshot to copy
        """
        self._logger.info(
            '->Copy the snapshot %s and encrypt it' % snapshot.id)
        snap_id = snapshot.copy(Description='encrypted copy of %s' % snapshot.id,
                                Encrypted=True, SourceRegion=self._region, KmsKeyId=self._kms_key)
        snapshot = self._ec2_resource.Snapshot(snap_id['SnapshotId'])

        # copy tags to snapshot
        tag_list = []

        if device.tags:
            # don't copy aws reserved tags
            tag_list = list(filter(
                lambda tag: not tag['Key'].startswith('aws:'), device.tags))

        snapshot.create_tags(Tags=tag_list)

        self._wait_snapshot.wait(SnapshotIds=[snapshot.id])
        return snapshot

    def _swap_device(self, old_volume, new_volume):
        """ Swap the old device with the new encrypted one
            :param old_volume: volume to detach from the instance
            :param new_volume: volume to attach to the instance
        """

        self._logger.info('->Swap the old volume and the new one')
        device = old_volume.attachments[0]['Device']
        self._instance.detach_volume(Device=device, VolumeId=old_volume.id)
        self._wait_volume.wait(VolumeIds=[old_volume.id])
        self._instance.attach_volume(Device=device, VolumeId=new_volume.id)

    def _take_snapshot(self, device):
        """ Take the first snapshot from the volume to encrypt
            :param device: EBS device to encrypt
        """

        self._logger.info('->Take a first snapshot for volume %s' % device.id)

        tag_list = []

        if device.tags:
            # don't copy aws reserved tags
            tag_list = list(filter(
                lambda tag: not tag['Key'].startswith('aws:'), device.tags))

        snapshot = device.create_snapshot(
            Description='snap of %s' % device.id,
            TagSpecifications=[{'ResourceType': 'snapshot', 'Tags': tag_list}])

        self._wait_snapshot.wait(SnapshotIds=[snapshot.id])
        return snapshot

    def start_encryption(self, discard_source):
        """ Launch encryption process """

        self._logger.info('Start to encrypt instance %s' % self._instance.id)

        def encrypt_all_volumes(device):
            self._logger.info(
                f"Starting encryption flow for device attachment {device.attachments[0]['Device']}")

           # Keep in mind if DeleteOnTermination is needed
            delete_flag = device.attachments[0]['DeleteOnTermination']
            flag_on = {'DeviceName': device.attachments[0]['Device'],
                       'Ebs': {'DeleteOnTermination':  delete_flag}}

            # First we have to take a snapshot from the original device
            snapshot = self._take_snapshot(device)
            # Then, copy this snapshot and encrypt it
            encrypted = self._encrypt_snapshot(snapshot, device)
            # Create a new volume from that encrypted snapshot
            volume = self._create_volume(encrypted, device)
            # Finally, swap the old-device for the new one
            self._swap_device(device, volume)
            # It's time to tidy up !
            self._cleanup(device, discard_source, snapshot, encrypted)
            # starting the stopped instance

            if not discard_source:
                self._logger.info('>Tagging legacy volume %s with replacement '
                                  'id %s' % (device.id, volume.id))
                device.create_tags(
                    Tags=[
                        {
                            'Key': 'encryptedReplacement',
                            'Value': volume.id
                        },
                    ]
                )

            if delete_flag:
                self._logger.info('->Put flag DeleteOnTermination on volume')
                self._instance.modify_attribute(BlockDeviceMappings=[flag_on])

            self._logger.info(f'''
                >The volume at attachment {device.attachments[0]['Device']} has been replaced with an encrypted volume.
                    Old volume id: {device.id}; new volume id: {volume.id}''')

        # We encrypt only EC2 EBS-backed. Support of instance store will be
        # added later
        for device in self._instance.block_device_mappings:
            if 'Ebs' not in device:
                msg = '%s: Skip %s not an EBS device' % (self._instance.id,
                                                         device['VolumeId'])
                self._logger.warning(msg)
                continue

        with ThreadPoolExecutor(max_workers=50, thread_name_prefix='_Thread_') as executor:

            for device in self._instance.volumes.all():
                if device.encrypted:
                    msg = '%s: Volume %s already encrypted' % (self._instance.id,
                                                                device.id)
                    self._logger.warning(msg)
                    continue

                self._logger.info(
                    f">Let\'s encrypt volume {device.id}, at attachment {device.attachments[0]['Device']}")

                # Fire off a separate thread to handle the encryption and swapping of each volume
                # (Also, if you have more than 50 volumes attached to an instance, we need to talk. :) )
                try:
                    executor.submit(encrypt_all_volumes, device)
                except Exception as error:
                    logger.error(f'General Exception, {error}')
                    sys.exit(1)

        self._start_instance()
        self._logger.info('End of work on instance %s\n' % self._instance.id)


def main(arguments):
    """ Start the main program """

    for instance in arguments.instances:
        try:
            EC2Cryptomatic(arguments.region, instance, arguments.key).start_encryption(
                arguments.discard_source)

        except (EndpointConnectionError, ValueError) as error:
            logger.error('Problem with your AWS region ? (%s)' % error)
            sys.exit(1)

        except (ClientError, TypeError) as error:
            logger.error('Problem with the instance (%s)' % error)
            continue

        except Exception as error:
            logger.error(f'General Exception, {error}')
            sys.exit(1)


if __name__ == '__main__':
    description = 'EC2Cryptomatic - Encrypt EBS volumes from EC2 instances'
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('-r', '--region', help='AWS Region', required=True)
    parser.add_argument('-i', '--instances', nargs='+',
                        help='Instance to encrypt', required=True)
    parser.add_argument(
        '-k', '--key', help="KMS Key ID. For alias, add prefix 'alias/'", default='alias/aws/ebs')
    parser.add_argument('-ds', '--discard_source', action='store_true', default=False,
                        help='Discard source volume after encryption (default: False)')
    args = parser.parse_args()
    main(args)
