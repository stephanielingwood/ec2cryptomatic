#!/usr/bin/env python3
# coding: utf-8

import argparse
import boto3
import logging
import os
import sys
import concurrent.futures
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

    def __init__(self, region: str, instance: str, key: str, timeout: int, profile: str):
        """ Constructor
            :param region: the AWS region where the instance is
            :param instance: one instance-id
            :param key: the AWS KMS Key to be used to encrypt the volume
            :param timeout: how many minutes a call should be allowed to run before timing out
        """
        self._logger = logging.getLogger('ec2-cryptomatic')
        self._logger.setLevel(logging.DEBUG)
        self._kms_key = key

        if profile:
            # If the user passes a specific AWS CLI profile, use that
            self._session = boto3.session.Session(profile_name=profile)
        else:
            # Otherwise, default to boto3's standard method for evaluating which profile to use
            self._session = boto3.session.Session()

        self._ec2_client = self._session.client('ec2', region_name=region)
        self._ec2_resource = self._session.resource('ec2', region_name=region)
        self._region = region
        self._instance = self._ec2_resource.Instance(id=instance)

        # Waiters
        self._wait_snapshot = self._ec2_client.get_waiter('snapshot_completed')
        self._wait_volume = self._ec2_client.get_waiter('volume_available')

        # Sets the timeout period for waiters, in max number of attempts
        # Waiter will poll every 15s; so, poll 4 times for each minute of timeout
        self._timeout = timeout
        self.max_attempts = self._timeout * 4
        self._wait_snapshot.config.max_attempts = self.max_attempts
        self._wait_volume.config.max_attempts = self.max_attempts

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
            :param discard_source: if true, the original volumes will be deleted
            :param snapshot: the temporary snapshot object created by _take_snapshot
            :param encrypted: the encrypted snapshot object created by _encrypt_snapshot
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
            :param original_device: a device object (attached volume) from the instance's attachments list
        """

        self._logger.info(
            '->Creating an encrypted volume from %s' % encrypted_snapshot.id)

        tag_list = []

        if original_device.tags:
            # don't copy aws reserved tags
            tag_list = list(filter(
                lambda tag: not tag['Key'].startswith('aws:'), original_device.tags))

        if original_device.volume_type == 'io1':
            # Iops parameter is required, and only used for, io1 volumes
            volume = self._ec2_resource.create_volume(
                SnapshotId=encrypted_snapshot.id,
                VolumeType=original_device.volume_type,
                AvailabilityZone=original_device.availability_zone,
                Iops=original_device.iops,
                TagSpecifications=[{'ResourceType': 'volume', 'Tags': tag_list}])
        else:
            volume = self._ec2_resource.create_volume(
                SnapshotId=encrypted_snapshot.id,
                VolumeType=original_device.volume_type,
                AvailabilityZone=original_device.availability_zone,
                TagSpecifications=[{'ResourceType': 'volume', 'Tags': tag_list}])

        self._logger.info(
            f'-> Creating encrypted volume {volume.id}')

        self._wait_volume.wait(VolumeIds=[volume.id])

        return volume

    def _encrypt_snapshot(self, snapshot, device):
        """ Copy and encrypt a snapshot
            :param snapshot: snapshot to copy
            :param device: a device object (attached volume) from the instance's attachments list
        """
        self._logger.info(
            '->Copy the snapshot %s and encrypt it' % snapshot.id)
        snap_id = snapshot.copy(Description='encrypted copy of %s' % snapshot.id,
                                Encrypted=True, SourceRegion=self._region, KmsKeyId=self._kms_key)
        snapshot = self._ec2_resource.Snapshot(snap_id['SnapshotId'])

        self._logger.info(
            f"->Creating encrypted snapshot {snap_id['SnapshotId']}")

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

        self._logger.info(
            f'->Creating unencrypted snapshot {snapshot.id}')

        self._wait_snapshot.wait(SnapshotIds=[snapshot.id])
        return snapshot

    def start_encryption(self, discard_source, start_instance):
        """ Launch encryption process
            :param discard_source: from arguments. If true, delete the original, unencypted volumes
            :param start_instance: from arguments. If true, restart the instance when encryption is complete
        """

        self._logger.info(f'Start to encrypt instance {self._instance.id}')
        self._logger.info(f'Timeout set to: {self._timeout} minutes')

        if start_instance:
            self._logger.info(f'Instance will be restarted after encryption')
        else:
            self._logger.info(f'Instance will remain stopped after encryption')

        def encrypt_all_volumes(device):
            '''Workflow to encrypt a given volume
                :param device: the device object to encrypt; from the instance's attachments list
            '''

            attachment = device.attachments[0]['Device']

            self._logger.info(
                f"Starting encryption flow for volume {device.id}, at attachment {attachment}")

           # Keep in mind if DeleteOnTermination is needed
            delete_flag = device.attachments[0]['DeleteOnTermination']
            flag_on = {'DeviceName': attachment,
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
                self._logger.info(
                    f'>Tagging legacy volume {device.id} with replacement id {volume.id}')
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
                >The volume at attachment {attachment} has been replaced with an encrypted volume.
                    Old volume id: {device.id}; new volume id: {volume.id}
                    Hooray!!!''')

        # We encrypt only EC2 EBS-backed. Support of instance store will be
        # added later
        for device in self._instance.block_device_mappings:
            if 'Ebs' not in device:
                self._logger.warning(
                    f"{self._instance.id}: Skip {device['VolumeId']}; not an EBS device")
                continue

        with concurrent.futures.ThreadPoolExecutor(max_workers=50, thread_name_prefix='_Thread_') as executor:
            unencrypted_volumes = list(filter(
                lambda volume: not volume.encrypted, self._instance.volumes.all()))
            self._logger.info(
                f'The following volumes are unencrypted, and will be encrypted: {unencrypted_volumes}')

            futures = {executor.submit(
                encrypt_all_volumes, device): device for device in unencrypted_volumes}

            for future in concurrent.futures.as_completed(futures):
                try:
                    data = future.result()
                except Exception as error:
                    logger.error(f'General Exception: {error}')
                    sys.exit(1)

        if start_instance:
            self._start_instance()

        self._logger.info(f'End of work on instance {self._instance.id}\n')


def main(arguments):
    """ Start the main program """

    for instance in arguments.instances:
        try:
            EC2Cryptomatic(arguments.region, instance, arguments.key, int(arguments.timeout), arguments.profile).start_encryption(
                arguments.discard_source, arguments.start_instance)

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
    parser.add_argument('-k', '--key',
                        help="KMS Key ID. For alias, add prefix 'alias/'", default='alias/aws/ebs')
    parser.add_argument('-t', '--timeout', default='20',
                        help="How many minutes you want to allow a snapshot or create-volume process to run before it times out")
    parser.add_argument('-ds', '--discard_source', action='store_true', default=False,
                        help='Discard source volume after encryption (default: False)')
    parser.add_argument('-s', '--start_instance', action='store_true', default=False,
                        help='Start instance after encrypting all attached volumes (default: False)')
    parser.add_argument('-p', '--profile', default='',
                        help='AWS profile to use for the AWS API calls. If not specified, the credentials you already have configured will be used.')
    args = parser.parse_args()
    main(args)
