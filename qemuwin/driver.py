# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# All Rights Reserved.
# Copyright (c) 2010 Citrix Systems, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
A fake (in-memory) hypervisor+api.

Allows nova testing w/o a hypervisor.  This module also documents the
semantics of real hypervisor connections.

"""

import functools
import os
import uuid

from oslo.config import cfg

from nova.api.metadata import base as instance_metadata
from nova import block_device
from nova.compute import power_state
from nova.compute import task_states
from nova import db
from nova import exception
from nova.openstack.common.gettextutils import _
from nova.openstack.common import log as logging
from nova.virt import driver
from nova.virt import virtapi
from nova.virt.qemuwin import blockinfo
from nova.virt.qemuwin import imagebackend
from nova.virt.qemuwin import imagecache
from nova.virt.qemuwin import utils as libvirt_utils
from nova.virt.disk import api as disk
from nova.compute import flavors
from nova import utils
from nova.virt import netutils
from nova.virt import driver
from nova.virt import configdrive
from nova.openstack.common import fileutils

CONF = cfg.CONF
CONF.import_opt('host', 'nova.netconf')

LOG = logging.getLogger(__name__)


_FAKE_NODES = None


def set_nodes(nodes):
    """Sets FakeDriver's node.list.

    It has effect on the following methods:
        get_available_nodes()
        get_available_resource
        get_host_stats()

    To restore the change, call restore_nodes()
    """
    global _FAKE_NODES
    _FAKE_NODES = nodes


def restore_nodes():
    """Resets FakeDriver's node list modified by set_nodes().

    Usually called from tearDown().
    """
    global _FAKE_NODES
    _FAKE_NODES = [CONF.host]


class FakeInstance(object):

    def __init__(self, name, state):
        self.name = name
        self.state = state

    def __getitem__(self, key):
        return getattr(self, key)


class QemuWinDriver(driver.ComputeDriver):
    capabilities = {
        "has_imagecache": True,
        "supports_recreate": True,
        }

    """Fake hypervisor driver."""

    def __init__(self, virtapi, read_only=False):
        super(QemuWinDriver, self).__init__(virtapi)
        print "fogbow.FakeDriver initialized"
        LOG.info("fogbow.FakeDriver initialized")
        self.instances = {}
        self.host_status_base = {
          'vcpus': 100000,
          'memory_mb': 8000000000,
          'local_gb': 600000000000,
          'vcpus_used': 0,
          'memory_mb_used': 0,
          'local_gb_used': 100000000000,
          'hypervisor_type': 'fogbow',
          'hypervisor_version': '2.1',
          'hypervisor_hostname': CONF.host,
          'cpu_info': {},
          'disk_available_least': 500000000000,
          }
        self._mounts = {}
        self._interfaces = {}
        self.image_backend = imagebackend.Backend(CONF.use_cow_images)
        if not _FAKE_NODES:
            set_nodes([CONF.host])

    def init_host(self, host):
        return

    def list_instances(self):
        return self.instances.keys()

    def plug_vifs(self, instance, network_info):
        """Plug VIFs into networks."""
        pass

    def unplug_vifs(self, instance, network_info):
        """Unplug VIFs from networks."""
        pass

		
	# initing qemu
	# qemu-system-i386.exe -m 64 -smp 1,sockets=1,cores=1,threads=1 -name instance-00000093 -uuid 964b523e-3da0-4770-a774-c08620b18603 -drive file=cirros-0.3.0-i386-disk.img,id=drive-virtio-disk0,if=none -device virtio-blk-pci,bus=pci.0,addr=0x4,drive=drive-virtio-disk0,id=virtio-disk0,bootindex=1 -chardev file,id=charserial0,path=console.log -device isa-serial,chardev=charserial0,id=serial0 -netdev user,id=hostnet0 -device virtio-net-pci,netdev=hostnet0,id=net0,mac=fa:16:3e:8a:35:33,bus=pci.0,addr=0x3 -smbios type=1,manufacturer=OpenStackFoundation,product=OpenStackNova,version=2013.2.4,serial=74cd34f4-f412-4438-8172-f44faadfa516,uuid=964b523e-3da0-4770-a774-c08620b18603 -usb -vnc 127.0.0.1:8 -k en-us -vga cirrus -device virtio-balloon-pci,id=balloon0,bus=pci.0,addr=0x5  -rtc base=utc,driftfix=slew -no-shutdown
    def spawn(self, context, instance, image_meta, injected_files,
              admin_password, network_info=None, block_device_info=None):
        name = instance['name']
        LOG.info("qemuwin.QemuWinDriver creating %s." % name)
        LOG.info("%s." % instance)
        state = power_state.RUNNING
        disk_info = blockinfo.get_disk_info('qemu',
                                            instance,
                                            block_device_info,
                                            image_meta)
        self._create_image(context, instance,
                           disk_info['mapping'],
                           network_info=network_info,
                           block_device_info=block_device_info,
                           files=injected_files,
                           admin_pass=admin_password)
        fake_instance = FakeInstance(name, state)
        self.instances[name] = fake_instance
		
    @staticmethod
    def _get_console_log_path(instance):
        return os.path.join(libvirt_utils.get_instance_path(instance),
                            'console.log')

    @staticmethod
    def _get_disk_config_path(instance):
        return os.path.join(libvirt_utils.get_instance_path(instance),
                            'disk.config')
		
    def _chown_console_log_for_instance(self, instance):
        console_log = self._get_console_log_path(instance)
        if os.path.exists(console_log):
            libvirt_utils.chown(console_log, os.getuid())

    def _chown_disk_config_for_instance(self, instance):
        disk_config = self._get_disk_config_path(instance)
        if os.path.exists(disk_config):
            libvirt_utils.chown(disk_config, os.getuid())
			
    @staticmethod
    def _create_local(target, local_size, unit='G',
                      fs_format=None, label=None):
        """Create a blank image of specified size."""

        if not fs_format:
            fs_format = CONF.default_ephemeral_format

        if not CONF.libvirt_images_type == "lvm":
            libvirt_utils.create_image('raw', target,
                                       '%d%c' % (local_size, unit))
        if fs_format:
            utils.mkfs(fs_format, target, label)

    def _create_ephemeral(self, target, ephemeral_size, fs_label, os_type,
                          max_size=None):
        self._create_local(target, ephemeral_size)
        disk.mkfs(os_type, fs_label, target)
		
    def _create_image(self, context, instance,
                      disk_mapping, suffix='',
                      disk_images=None, network_info=None,
                      block_device_info=None, files=None,
                      admin_pass=None, inject_files=True):
        if not suffix:
            suffix = ''

        booted_from_volume = (
            (not bool(instance.get('image_ref')))
            or 'disk' not in disk_mapping
        )

        # syntactic nicety
        def basepath(fname='', suffix=suffix):
            return os.path.join(libvirt_utils.get_instance_path(instance),
                                fname + suffix)

        def image(fname, image_type=CONF.libvirt_images_type):
            return self.image_backend.image(instance,
                                            fname + suffix, image_type)

        def raw(fname):
            return image(fname, image_type='raw')

        # ensure directories exist and are writable
        fileutils.ensure_tree(basepath(suffix=''))

        LOG.info(_('Creating image'), instance=instance)

        # NOTE(dprince): for rescue console.log may already exist... chown it.
        self._chown_console_log_for_instance(instance)

        # NOTE(yaguang): For evacuate disk.config already exist in shared
        # storage, chown it.
        self._chown_disk_config_for_instance(instance)

        # NOTE(vish): No need add the suffix to console.log
        libvirt_utils.write_to_file(
            self._get_console_log_path(instance), '', 7)

        if not disk_images:
            disk_images = {'image_id': instance['image_ref'],
                           'kernel_id': instance['kernel_id'],
                           'ramdisk_id': instance['ramdisk_id']}

        if disk_images['kernel_id']:
            fname = imagecache.get_cache_fname(disk_images, 'kernel_id')
            raw('kernel').cache(fetch_func=libvirt_utils.fetch_image,
                                context=context,
                                filename=fname,
                                image_id=disk_images['kernel_id'],
                                user_id=instance['user_id'],
                                project_id=instance['project_id'])
            if disk_images['ramdisk_id']:
                fname = imagecache.get_cache_fname(disk_images, 'ramdisk_id')
                raw('ramdisk').cache(fetch_func=libvirt_utils.fetch_image,
                                     context=context,
                                     filename=fname,
                                     image_id=disk_images['ramdisk_id'],
                                     user_id=instance['user_id'],
                                     project_id=instance['project_id'])

        inst_type = flavors.extract_flavor(instance)

        # NOTE(ndipanov): Even if disk_mapping was passed in, which
        # currently happens only on rescue - we still don't want to
        # create a base image.
        if not booted_from_volume:
            root_fname = imagecache.get_cache_fname(disk_images, 'image_id')
            size = instance['root_gb'] * 1024 * 1024 * 1024

            if size == 0 or suffix == '.rescue':
                size = None

            image('disk').cache(fetch_func=libvirt_utils.fetch_image,
                                context=context,
                                filename=root_fname,
                                size=size,
                                image_id=disk_images['image_id'],
                                user_id=instance['user_id'],
                                project_id=instance['project_id'])

        # Lookup the filesystem type if required
        os_type_with_default = disk.get_fs_type_for_os_type(
                                                          instance['os_type'])

        ephemeral_gb = instance['ephemeral_gb']
        if 'disk.local' in disk_mapping:
            fn = functools.partial(self._create_ephemeral,
                                   fs_label='ephemeral0',
                                   os_type=instance["os_type"])
            fname = "ephemeral_%s_%s" % (ephemeral_gb, os_type_with_default)
            size = ephemeral_gb * 1024 * 1024 * 1024
            image('disk.local').cache(fetch_func=fn,
                                      filename=fname,
                                      size=size,
                                      ephemeral_size=ephemeral_gb)

        for idx, eph in enumerate(driver.block_device_info_get_ephemerals(
                block_device_info)):
            fn = functools.partial(self._create_ephemeral,
                                   fs_label='ephemeral%d' % idx,
                                   os_type=instance["os_type"])
            size = eph['size'] * 1024 * 1024 * 1024
            fname = "ephemeral_%s_%s" % (eph['size'], os_type_with_default)
            image(blockinfo.get_eph_disk(idx)).cache(
                fetch_func=fn,
                filename=fname,
                size=size,
                ephemeral_size=eph['size'])

        if 'disk.swap' in disk_mapping:
            mapping = disk_mapping['disk.swap']
            swap_mb = 0

            swap = driver.block_device_info_get_swap(block_device_info)
            if driver.swap_is_usable(swap):
                swap_mb = swap['swap_size']
            elif (inst_type['swap'] > 0 and
                  not block_device.volume_in_mapping(
                    mapping['dev'], block_device_info)):
                swap_mb = inst_type['swap']

            if swap_mb > 0:
                size = swap_mb * 1024 * 1024
                image('disk.swap').cache(fetch_func=self._create_swap,
                                         filename="swap_%s" % swap_mb,
                                         size=size,
                                         swap_mb=swap_mb)

        # Config drive
        if configdrive.required_by(instance):
            LOG.info(_('Using config drive'), instance=instance)
            extra_md = {}
            if admin_pass:
                extra_md['admin_pass'] = admin_pass

            inst_md = instance_metadata.InstanceMetadata(instance,
                content=files, extra_md=extra_md, network_info=network_info)
            with configdrive.ConfigDriveBuilder(instance_md=inst_md) as cdb:
                configdrive_path = basepath(fname='disk.config')
                LOG.info(_('Creating config drive at %(path)s'),
                         {'path': configdrive_path}, instance=instance)

                try:
                    cdb.make_drive(configdrive_path)
                except processutils.ProcessExecutionError as e:
                    with excutils.save_and_reraise_exception():
                        LOG.error(_('Creating config drive failed '
                                  'with error: %s'),
                                  e, instance=instance)

        # File injection only if needed
        elif inject_files and CONF.libvirt_inject_partition != -2:

            if booted_from_volume:
                LOG.warn(_('File injection into a boot from volume '
                           'instance is not supported'), instance=instance)

            target_partition = None
            if not instance['kernel_id']:
                target_partition = CONF.libvirt_inject_partition
                if target_partition == 0:
                    target_partition = None
            if CONF.libvirt_type == 'lxc':
                target_partition = None

            if CONF.libvirt_inject_key and instance['key_data']:
                key = str(instance['key_data'])
            else:
                key = None

            net = netutils.get_injected_network_template(network_info)

            metadata = instance.get('metadata')

            if not CONF.libvirt_inject_password:
                admin_pass = None

            if any((key, net, metadata, admin_pass, files)):
                # If we're not using config_drive, inject into root fs
                injection_path = image('disk').path
                img_id = instance['image_ref']

                for inj, val in [('key', key),
                                 ('net', net),
                                 ('metadata', metadata),
                                 ('admin_pass', admin_pass),
                                 ('files', files)]:
                    if val:
                        LOG.info(_('Injecting %(inj)s into image '
                                   '%(img_id)s'),
                                 {'inj': inj, 'img_id': img_id},
                                 instance=instance)
                try:
                    disk.inject_data(injection_path,
                                     key, net, metadata, admin_pass, files,
                                     partition=target_partition,
                                     use_cow=CONF.use_cow_images,
                                     mandatory=('files',))
                except Exception as e:
                    with excutils.save_and_reraise_exception():
                        LOG.error(_('Error injecting data into image '
                                    '%(img_id)s (%(e)s)'),
                                  {'img_id': img_id, 'e': e},
                                  instance=instance)

        if CONF.libvirt_type == 'uml':
            libvirt_utils.chown(image('disk').path, 'root')

    def live_snapshot(self, context, instance, name, update_task_state):
        if instance['name'] not in self.instances:
            raise exception.InstanceNotRunning(instance_id=instance['uuid'])
        update_task_state(task_state=task_states.IMAGE_UPLOADING)

    def snapshot(self, context, instance, name, update_task_state):
        if instance['name'] not in self.instances:
            raise exception.InstanceNotRunning(instance_id=instance['uuid'])
        update_task_state(task_state=task_states.IMAGE_UPLOADING)

    def reboot(self, context, instance, network_info, reboot_type,
               block_device_info=None, bad_volumes_callback=None):
        pass

    @staticmethod
    def get_host_ip_addr():
        return '192.168.0.1'

    def set_admin_password(self, instance, new_pass):
        pass

    def inject_file(self, instance, b64_path, b64_contents):
        pass

    def resume_state_on_host_boot(self, context, instance, network_info,
                                  block_device_info=None):
        pass

    def rescue(self, context, instance, network_info, image_meta,
               rescue_password):
        pass

    def unrescue(self, instance, network_info):
        pass

    def poll_rebooting_instances(self, timeout, instances):
        pass

    def migrate_disk_and_power_off(self, context, instance, dest,
                                   instance_type, network_info,
                                   block_device_info=None):
        pass

    def finish_revert_migration(self, instance, network_info,
                                block_device_info=None, power_on=True):
        pass

    def post_live_migration_at_destination(self, context, instance,
                                           network_info,
                                           block_migration=False,
                                           block_device_info=None):
        pass

    def power_off(self, instance):
        pass

    def power_on(self, context, instance, network_info, block_device_info):
        pass

    def soft_delete(self, instance):
        pass

    def restore(self, instance):
        pass

    def pause(self, instance):
        pass

    def unpause(self, instance):
        pass

    def suspend(self, instance):
        pass

    def resume(self, context, instance, network_info, block_device_info=None):
        pass

    def destroy(self, instance, network_info, block_device_info=None,
                destroy_disks=True, context=None):
        key = instance['name']
        if key in self.instances:
            del self.instances[key]
        else:
            LOG.warning(_("Key '%(key)s' not in instances '%(inst)s'") %
                        {'key': key,
                         'inst': self.instances}, instance=instance)

    def attach_volume(self, context, connection_info, instance, mountpoint,
                      encryption=None):
        """Attach the disk to the instance at mountpoint using info."""
        instance_name = instance['name']
        if instance_name not in self._mounts:
            self._mounts[instance_name] = {}
        self._mounts[instance_name][mountpoint] = connection_info
        return True

    def detach_volume(self, connection_info, instance, mountpoint,
                      encryption=None):
        """Detach the disk attached to the instance."""
        try:
            del self._mounts[instance['name']][mountpoint]
        except KeyError:
            pass
        return True

    def swap_volume(self, old_connection_info, new_connection_info,
                    instance, mountpoint):
        """Replace the disk attached to the instance."""
        instance_name = instance['name']
        if instance_name not in self._mounts:
            self._mounts[instance_name] = {}
        self._mounts[instance_name][mountpoint] = new_connection_info
        return True

    def attach_interface(self, instance, image_meta, vif):
        if vif['id'] in self._interfaces:
            raise exception.InterfaceAttachFailed('duplicate')
        self._interfaces[vif['id']] = vif

    def detach_interface(self, instance, vif):
        try:
            del self._interfaces[vif['id']]
        except KeyError:
            raise exception.InterfaceDetachFailed('not attached')

    def get_info(self, instance):
        if instance['name'] not in self.instances:
            raise exception.InstanceNotFound(instance_id=instance['name'])
        i = self.instances[instance['name']]
        return {'state': i.state,
                'max_mem': 0,
                'mem': 0,
                'num_cpu': 2,
                'cpu_time': 0}

    def get_diagnostics(self, instance_name):
        return {'cpu0_time': 17300000000,
                'memory': 524288,
                'vda_errors': -1,
                'vda_read': 262144,
                'vda_read_req': 112,
                'vda_write': 5778432,
                'vda_write_req': 488,
                'vnet1_rx': 2070139,
                'vnet1_rx_drop': 0,
                'vnet1_rx_errors': 0,
                'vnet1_rx_packets': 26701,
                'vnet1_tx': 140208,
                'vnet1_tx_drop': 0,
                'vnet1_tx_errors': 0,
                'vnet1_tx_packets': 662,
        }

    def get_all_bw_counters(self, instances):
        """Return bandwidth usage counters for each interface on each
           running VM.
        """
        bw = []
        return bw

    def get_all_volume_usage(self, context, compute_host_bdms):
        """Return usage info for volumes attached to vms on
           a given host.
        """
        volusage = []
        return volusage

    def block_stats(self, instance_name, disk_id):
        return [0L, 0L, 0L, 0L, None]

    def interface_stats(self, instance_name, iface_id):
        return [0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L]

    def get_console_output(self, instance):
        return 'FAKE CONSOLE OUTPUT\nANOTHER\nLAST LINE'

    def get_vnc_console(self, instance):
        return {'internal_access_path': 'FAKE',
                'host': 'fakevncconsole.com',
                'port': 6969}

    def get_spice_console(self, instance):
        return {'internal_access_path': 'FAKE',
                'host': 'fakespiceconsole.com',
                'port': 6969,
                'tlsPort': 6970}

    def get_console_pool_info(self, console_type):
        return {'address': '127.0.0.1',
                'username': 'fakeuser',
                'password': 'fakepassword'}

    def refresh_security_group_rules(self, security_group_id):
        return True

    def refresh_security_group_members(self, security_group_id):
        return True

    def refresh_instance_security_rules(self, instance):
        return True

    def refresh_provider_fw_rules(self):
        pass

    def get_available_resource(self, nodename):
        """Updates compute manager resource info on ComputeNode table.

           Since we don't have a real hypervisor, pretend we have lots of
           disk and ram.
        """
        if nodename not in _FAKE_NODES:
            return {}

        dic = {'vcpus': 1,
               'memory_mb': 8192,
               'local_gb': 1028,
               'vcpus_used': 0,
               'memory_mb_used': 0,
               'local_gb_used': 0,
               'hypervisor_type': 'fake',
               'hypervisor_version': '1.0',
               'hypervisor_hostname': nodename,
               'disk_available_least': 0,
               'cpu_info': '?'}
        return dic

    def ensure_filtering_rules_for_instance(self, instance_ref, network_info):
        return

    def get_instance_disk_info(self, instance_name):
        return

    def live_migration(self, context, instance_ref, dest,
                       post_method, recover_method, block_migration=False,
                       migrate_data=None):
        post_method(context, instance_ref, dest, block_migration,
                            migrate_data)
        return

    def check_can_live_migrate_destination_cleanup(self, ctxt,
                                                   dest_check_data):
        return

    def check_can_live_migrate_destination(self, ctxt, instance_ref,
                                           src_compute_info, dst_compute_info,
                                           block_migration=False,
                                           disk_over_commit=False):
        return {}

    def check_can_live_migrate_source(self, ctxt, instance_ref,
                                      dest_check_data):
        return

    def finish_migration(self, context, migration, instance, disk_info,
                         network_info, image_meta, resize_instance,
                         block_device_info=None, power_on=True):
        return

    def confirm_migration(self, migration, instance, network_info):
        return

    def pre_live_migration(self, context, instance_ref, block_device_info,
                           network_info, disk, migrate_data=None):
        return

    def unfilter_instance(self, instance_ref, network_info):
        return

    def test_remove_vm(self, instance_name):
        """Removes the named VM, as if it crashed. For testing."""
        self.instances.pop(instance_name)

    def get_host_stats(self, refresh=False):
        """Return fake Host Status of ram, disk, network."""
        stats = []
        for nodename in _FAKE_NODES:
            host_status = self.host_status_base.copy()
            host_status['hypervisor_hostname'] = nodename
            host_status['host_hostname'] = nodename
            host_status['host_name_label'] = nodename
            stats.append(host_status)
        if len(stats) == 0:
            raise exception.NovaException("FakeDriver has no node")
        elif len(stats) == 1:
            return stats[0]
        else:
            return stats

    def host_power_action(self, host, action):
        """Reboots, shuts down or powers up the host."""
        return action

    def host_maintenance_mode(self, host, mode):
        """Start/Stop host maintenance window. On start, it triggers
        guest VMs evacuation.
        """
        if not mode:
            return 'off_maintenance'
        return 'on_maintenance'

    def set_host_enabled(self, host, enabled):
        """Sets the specified host's ability to accept new instances."""
        if enabled:
            return 'enabled'
        return 'disabled'

    def get_disk_available_least(self):
        pass

    def add_to_aggregate(self, context, aggregate, host, **kwargs):
        pass

    def remove_from_aggregate(self, context, aggregate, host, **kwargs):
        pass

    def get_volume_connector(self, instance):
        return {'ip': '127.0.0.1', 'initiator': 'fake', 'host': 'fakehost'}

    def get_available_nodes(self, refresh=False):
        return _FAKE_NODES

    def instance_on_disk(self, instance):
        return False

    def list_instance_uuids(self):
        return []


class FakeVirtAPI(virtapi.VirtAPI):
    def instance_update(self, context, instance_uuid, updates):
        return db.instance_update_and_get_original(context,
                                                   instance_uuid,
                                                   updates)

    def aggregate_get_by_host(self, context, host, key=None):
        return db.aggregate_get_by_host(context, host, key=key)

    def aggregate_metadata_add(self, context, aggregate, metadata,
                               set_delete=False):
        return db.aggregate_metadata_add(context, aggregate['id'], metadata,
                                         set_delete=set_delete)

    def aggregate_metadata_delete(self, context, aggregate, key):
        return db.aggregate_metadata_delete(context, aggregate['id'], key)

    def security_group_get_by_instance(self, context, instance):
        return db.security_group_get_by_instance(context, instance['uuid'])

    def security_group_rule_get_by_security_group(self, context,
                                                  security_group):
        return db.security_group_rule_get_by_security_group(
            context, security_group['id'])

    def provider_fw_rule_get_all(self, context):
        return db.provider_fw_rule_get_all(context)

    def agent_build_get_by_triple(self, context, hypervisor, os, architecture):
        return db.agent_build_get_by_triple(context,
                                            hypervisor, os, architecture)

    def instance_type_get(self, context, instance_type_id):
        return db.instance_type_get(context, instance_type_id)

    def block_device_mapping_get_all_by_instance(self, context, instance,
                                                 legacy=True):
        bdms = db.block_device_mapping_get_all_by_instance(context,
                                                           instance['uuid'])
        if legacy:
            bdms = block_device.legacy_mapping(bdms)
        return bdms

    def block_device_mapping_update(self, context, bdm_id, values):
        return db.block_device_mapping_update(context, bdm_id, values)
