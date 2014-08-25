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

import errno
import eventlet
import functools
import glob
import os
import shutil
import socket
import sys
import tempfile
import threading
import time
import uuid
import subprocess
import json
import ctypes
import socket
import platform
import wmi

from eventlet import greenio
from eventlet import greenthread
from eventlet import patcher
from eventlet import tpool
from eventlet import util as eventlet_util
from xml.dom import minidom
from lxml import etree
from oslo.config import cfg

from nova.api.metadata import base as instance_metadata
from nova import block_device
from nova.compute import flavors
from nova.compute import power_state
from nova.compute import task_states
from nova.compute import utils as compute_utils
from nova.compute import vm_mode
from nova.compute import power_state
from nova import context as nova_context
from nova import exception
from nova.image import glance
from nova import notifier
from nova.objects import instance as instance_obj
from nova.openstack.common import excutils
from nova.openstack.common import fileutils
from nova.openstack.common.gettextutils import _
from nova.openstack.common import importutils
from nova.openstack.common import jsonutils
from nova.openstack.common import log as logging
from nova.openstack.common import loopingcall
from nova.openstack.common import processutils
from nova.openstack.common import xmlutils
from nova.pci import pci_manager
from nova.pci import pci_utils
from nova.pci import pci_whitelist
from nova import utils
from nova import version
from nova.virt import configdrive
from nova.virt.disk import api as disk
from nova.virt import driver
from nova.virt import virtapi
from nova.virt import event as virtevent
from nova.virt import firewall
from nova.virt.qemuwin import blockinfo
from nova.virt.qemuwin import config as vconfig
from nova.virt.qemuwin import firewall as libvirt_firewall
from nova.virt.qemuwin import imagebackend
from nova.virt.qemuwin import imagecache
from nova.virt.qemuwin import utils as libvirt_utils
from nova.virt.qemuwin import images
from nova.virt import netutils
from nova import volume
from nova.volume import encryptors


libvirt_opts = [
    cfg.StrOpt('rescue_image_id',
               help='Rescue ami image'),
    cfg.StrOpt('rescue_kernel_id',
               help='Rescue aki image'),
    cfg.StrOpt('rescue_ramdisk_id',
               help='Rescue ari image'),
    cfg.StrOpt('libvirt_uri',
               default='',
               help='Override the default libvirt URI '
                    '(which is dependent on libvirt_type)'),
    cfg.BoolOpt('libvirt_inject_password',
                default=False,
                help='Inject the admin password at boot time, '
                     'without an agent.'),
    cfg.BoolOpt('libvirt_inject_key',
                default=True,
                help='Inject the ssh public key at boot time'),
    cfg.IntOpt('libvirt_inject_partition',
                default=1,
                help='The partition to inject to : '
                     '-2 => disable, -1 => inspect (libguestfs only), '
                     '0 => not partitioned, >0 => partition number'),
    cfg.BoolOpt('use_usb_tablet',
                default=True,
                help='Sync virtual and real mouse cursors in Windows VMs'),
    cfg.StrOpt('live_migration_uri',
               default="qemu+tcp://%s/system",
               help='Migration target URI '
                    '(any included "%s" is replaced with '
                    'the migration target hostname)'),
    cfg.StrOpt('live_migration_flag',
               default='VIR_MIGRATE_UNDEFINE_SOURCE, VIR_MIGRATE_PEER2PEER',
               help='Migration flags to be set for live migration'),
    cfg.StrOpt('block_migration_flag',
               default='VIR_MIGRATE_UNDEFINE_SOURCE, VIR_MIGRATE_PEER2PEER, '
                       'VIR_MIGRATE_NON_SHARED_INC',
               help='Migration flags to be set for block migration'),
    cfg.IntOpt('live_migration_bandwidth',
               default=0,
               help='Maximum bandwidth to be used during migration, in Mbps'),
    cfg.StrOpt('snapshot_image_format',
               help='Snapshot image format (valid options are : '
                    'raw, qcow2, vmdk, vdi). '
                    'Defaults to same as source image'),
    cfg.StrOpt('qemuwin_vif_driver',
               default='nova.virt.qemuwin.vif.LibvirtGenericVIFDriver',
               help='The libvirt VIF driver to configure the VIFs.'),
    cfg.ListOpt('qemuwin_volume_drivers',
                default=[
                  'iscsi=nova.virt.qemuwin.volume.LibvirtISCSIVolumeDriver',
                  'iser=nova.virt.qemuwin.volume.LibvirtISERVolumeDriver',
                  'local=nova.virt.qemuwin.volume.LibvirtVolumeDriver',
                  'fake=nova.virt.qemuwin.volume.LibvirtFakeVolumeDriver',
                  'rbd=nova.virt.qemuwin.volume.LibvirtNetVolumeDriver',
                  'sheepdog=nova.virt.qemuwin.volume.LibvirtNetVolumeDriver',
                  'nfs=nova.virt.qemuwin.volume.LibvirtNFSVolumeDriver',
                  'aoe=nova.virt.qemuwin.volume.LibvirtAOEVolumeDriver',
                  'glusterfs='
                      'nova.virt.qemuwin.volume.LibvirtGlusterfsVolumeDriver',
                  'fibre_channel=nova.virt.qemuwin.volume.'
                      'LibvirtFibreChannelVolumeDriver',
                  'scality='
                      'nova.virt.qemuwin.volume.LibvirtScalityVolumeDriver',
                  ],
                help='Libvirt handlers for remote volumes.'),
    cfg.StrOpt('libvirt_disk_prefix',
               help='Override the default disk prefix for the devices attached'
                    ' to a server, which is dependent on libvirt_type. '
                    '(valid options are: sd, xvd, uvd, vd)'),
    cfg.IntOpt('libvirt_wait_soft_reboot_seconds',
               default=120,
               help='Number of seconds to wait for instance to shut down after'
                    ' soft reboot request is made. We fall back to hard reboot'
                    ' if instance does not shutdown within this window.'),
    cfg.BoolOpt('libvirt_nonblocking',
                default=True,
                help='Use a separated OS thread pool to realize non-blocking'
                     ' libvirt calls'),
    cfg.StrOpt('libvirt_cpu_mode',
               help='Set to "host-model" to clone the host CPU feature flags; '
                    'to "host-passthrough" to use the host CPU model exactly; '
                    'to "custom" to use a named CPU model; '
                    'to "none" to not set any CPU model. '
                    'If libvirt_type="kvm|qemu", it will default to '
                    '"host-model", otherwise it will default to "none"'),
    cfg.StrOpt('libvirt_cpu_model',
               help='Set to a named libvirt CPU model (see names listed '
                    'in /usr/share/libvirt/cpu_map.xml). Only has effect if '
                    'libvirt_cpu_mode="custom" and libvirt_type="kvm|qemu"'),
    cfg.StrOpt('libvirt_snapshots_directory',
               default='$instances_path/snapshots',
               help='Location where libvirt driver will store snapshots '
                    'before uploading them to image service'),
    cfg.StrOpt('xen_hvmloader_path',
                default='/usr/lib/xen/boot/hvmloader',
                help='Location where the Xen hvmloader is kept'),
    cfg.ListOpt('disk_cachemodes',
                 default=[],
                 help='Specific cachemodes to use for different disk types '
                      'e.g: ["file=directsync","block=none"]'),
    cfg.StrOpt('vcpu_pin_set',
                help='Which pcpus can be used by vcpus of instance '
                     'e.g: "4-12,^8,15"'),
    cfg.StrOpt('nova_metadata_host',
                help='IP address used by Nova metadata server.'),
    cfg.IntOpt('nova_metadata_port',
                default=8775,
                help='TCP Port used by Nova metadata server.'),
    cfg.StrOpt('nova_metadata_shared_secret',
                default='',
                help='Shared secret to sign instance-id request'),
    cfg.StrOpt('qemu_home',
                default=None,
                help='Path to home directory of QEMU binaries.'),
    cfg.StrOpt('python_home',
                default=None,
                help='Path to python home directory.')
    ]

CONF = cfg.CONF
CONF.register_opts(libvirt_opts)
CONF.import_opt('host', 'nova.netconf')
CONF.import_opt('my_ip', 'nova.netconf')
CONF.import_opt('default_ephemeral_format', 'nova.virt.driver')
CONF.import_opt('use_cow_images', 'nova.virt.driver')
CONF.import_opt('live_migration_retry_count', 'nova.compute.manager')
CONF.import_opt('vncserver_proxyclient_address', 'nova.vnc')
CONF.import_opt('vncserver_listen', 'nova.vnc')
CONF.import_opt('server_proxyclient_address', 'nova.spice', group='spice')
CONF.import_opt('instances_path', 'nova.compute.manager')

HYPERVISOR_TYPE = 'qemu'
HYPERVISOR_VERSION = '2.1.0'
INSTANCE_METADATA_FILE = 'metadata'

MAX_CONSOLE_BYTES = 102400
PROCESS_TERMINATE = 1
VNC_BASE_PORT = 5900
QMP_CAPABILITY_WAIT = 3
SOCKET_NOT_BOUND = 10061
POWEROFF_RETRIES = 120
POWEROFF_RETRY_INTERVAL = 1

QMP_REBOOT_COMMAND = 'system_reset'
QMP_SUSPEND_COMMAND = 'stop'
QMP_RESUME_COMMAND = 'cont'
QMP_STOP_COMMAND = 'quit'
QMP_SHUTDOWN_COMMAND = 'system_powerdown'
QMP_MACHINE_STATUS = 'query-status'
QMP_QUERY_CPUS = 'query-cpus'
QMP_HUMAN_MONITOR_COMMAND = 'human-monitor-command'
QMP_COMMAND_LINE = 'command-line'

# iSCSI constants
ISCSI_CLI = 'iscsicli.exe'
ISCSI_LOGIN_CMD = 'qlogintarget'
ISCSI_LOGOUT_CMD = 'logouttarget'
ISCSI_LIST_TARGETS_CMD = 'ListTargets'
ISCSI_LIST_SESSIONS_CMD = 'SessionList'
ISCSI_TARGET_MAPPINGS_CMD = 'reporttargetmappings'
ISCSI_ADD_TARGET_PORTAL_CMD = 'QAddTargetPortal'
ISCSI_COMMAND_END_MESSAGE = 'The operation completed successfully.'

LOG = logging.getLogger(__name__)

_NODES = None

def set_nodes(nodes):
    """Sets FakeDriver's node.list.

    It has effect on the following methods:
        get_available_nodes()
        get_available_resource
        get_host_stats()

    To restore the change, call restore_nodes()
    """
    global _NODES
    _NODES = nodes


def restore_nodes():
    """Resets FakeDriver's node list modified by set_nodes().

    Usually called from tearDown().
    """
    global _NODES
    _NODES = [CONF.host]

class QemuWinDriver(driver.ComputeDriver):
    capabilities = {
        "has_imagecache": True,
        "supports_recreate": True,
        }

    """Fake hypervisor driver."""

    def __init__(self, virtapi, read_only=False):
        super(QemuWinDriver, self).__init__(virtapi)
        LOG.info("fogbow.QemuWinDriver initialized")
        LOG.info("QEMUWINDRIVER: qemu home: %s" % (CONF.qemu_home))
        self._caps = None
        self._disk_cachemode = None
        
        self.image_backend = imagebackend.Backend(CONF.use_cow_images)
        self.disk_cachemodes = {}

        self.valid_cachemodes = ["default",
                                 "none",
                                 "writethrough",
                                 "writeback",
                                 "directsync",
                                 "unsafe",
                                ]

        vif_class = importutils.import_class(CONF.qemuwin_vif_driver)
        self.vif_driver = vif_class(None)

        for mode_str in CONF.disk_cachemodes:
            disk_type, sep, cache_mode = mode_str.partition('=')
            if cache_mode not in self.valid_cachemodes:
                LOG.warn(_('Invalid cachemode %(cache_mode)s specified '
                           'for disk type %(disk_type)s.'),
                         {'cache_mode': cache_mode, 'disk_type': disk_type})
                continue
            self.disk_cachemodes[disk_type] = cache_mode

        if not _NODES:
            set_nodes([CONF.host])

    def init_host(self, host):
        return

    def list_instances(self):
      instance_dir = CONF.instances_path
      instance_dir_children = [x[0] for x in os.walk(instance_dir)]
      instance_list = []
      for child in instance_dir_children:
          if os.path.isfile(os.path.join(child, INSTANCE_METADATA_FILE)):
              instance_list.append(os.path.basename(child))
      return instance_list

    def plug_vifs(self, instance, network_info):
        """Plug VIFs into networks."""
        pass

    def unplug_vifs(self, instance, network_info):
        """Unplug VIFs from networks."""
        pass

    @property
    def disk_cachemode(self):
        if self._disk_cachemode is None:
            # We prefer 'none' for consistent performance, host crash
            # safety & migration correctness by avoiding host page cache.
            # Some filesystems (eg GlusterFS via FUSE) don't support
            # O_DIRECT though. For those we fallback to 'writethrough'
            # which gives host crash safety, and is safe for migration
            # provided the filesystem is cache coherant (cluster filesystems
            # typically are, but things like NFS are not).
            self._disk_cachemode = "none"
            if not self._supports_direct_io(CONF.instances_path):
                self._disk_cachemode = "writethrough"
        return self._disk_cachemode
   
    @staticmethod
    def _supports_direct_io(dirpath):

        if not hasattr(os, 'O_DIRECT'):
            LOG.debug(_("This python runtime does not support direct I/O"))
            return False

        testfile = os.path.join(dirpath, ".directio.test")

        hasDirectIO = True
        try:
            f = os.open(testfile, os.O_CREAT | os.O_WRONLY | os.O_DIRECT)
            os.close(f)
            LOG.debug(_("Path '%(path)s' supports direct I/O") %
                      {'path': dirpath})
        except OSError as e:
            if e.errno == errno.EINVAL:
                LOG.debug(_("Path '%(path)s' does not support direct I/O: "
                            "'%(ex)s'") % {'path': dirpath, 'ex': str(e)})
                hasDirectIO = False
            else:
                with excutils.save_and_reraise_exception():
                    LOG.error(_("Error on '%(path)s' while checking "
                                "direct I/O: '%(ex)s'") %
                                {'path': dirpath, 'ex': str(e)})
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error(_("Error on '%(path)s' while checking direct I/O: "
                            "'%(ex)s'") % {'path': dirpath, 'ex': str(e)})
        finally:
            try:
                os.unlink(testfile)
            except Exception:
                pass

        return hasDirectIO

    @staticmethod
    def getEl(dom, elName):
        return dom.getElementsByTagName(elName)[0]

    @staticmethod
    def getEls(dom, elsName):
        return dom.getElementsByTagName(elsName)

    @staticmethod
    def getText(dom, elName):
        return dom.getElementsByTagName(elName)[0].childNodes[0].nodeValue

    @staticmethod
    def qemuCommandNew(arch):
        qemu_command = 'qemu-system-x86_64.exe'
        if CONF.qemu_home is not None:
            qemu_command = os.path.join(CONF.qemu_home, 'qemu-system-x86_64.exe')
        LOG.debug('QEMUWINDRIVER: qemu binary location: %s' % (qemu_command))
        return [qemu_command]

    @staticmethod
    def qemuCommandAddArg(cmd, argName, argValue):
        cmd.append(argName)
        cmd.append(argValue)

    @staticmethod
    def qemuCommandStr(cmd):
        return ' '.join(cmd)

    def _create_qemu_machine(self, instance):
        instance_dir = libvirt_utils.get_instance_path(instance)
        xml_path = os.path.join(instance_dir, 'libvirt.xml')
        dom = minidom.parse(xml_path)
        cpu = self.getEl(dom, 'cpu')
        arch = self.getText(cpu, 'arch')
        cmd = self.qemuCommandNew(arch)

        memory = int(self.getText(dom, 'memory'))/1024
        self.qemuCommandAddArg(cmd, '-m', str(memory))
        self.qemuCommandAddArg(cmd, '-smp', '1,sockets=1,cores=1,threads=1')

        name = self.getText(dom, 'name')
        self.qemuCommandAddArg(cmd, '-name', name)

        uuid = self.getText(dom, 'uuid')
        self.qemuCommandAddArg(cmd, '-uuid', uuid)

        vcpu = self.getText(dom, 'vcpu')

        devices = self.getEl(dom, 'devices')
        disk = self.getEl(devices, 'disk')
        diskSource = self.getEl(disk, 'source')
        self.qemuCommandAddArg(cmd, '-drive', 'file=%s,id=drive-virtio-disk0,if=none' % diskSource.attributes['file'].value)
        self.qemuCommandAddArg(cmd, '-device', 'virtio-blk-pci,bus=pci.0,addr=0x4,drive=drive-virtio-disk0,id=virtio-disk0,bootindex=1')

        serial = self.getEl(devices, 'serial')
        serialSource = self.getEl(serial, 'source')
        self.qemuCommandAddArg(cmd, '-chardev', 'file,id=charserial0,path=%s' % serialSource.attributes['path'].value)
        self.qemuCommandAddArg(cmd, '-device', 'isa-serial,chardev=charserial0,id=serial0')

        metadata_port, metadata_pid = self._start_metadata_proxy(instance['uuid'], instance['project_id'])

        interface = self.getEl(devices, 'interface')
        mac = self.getEl(interface, 'mac')
        self.qemuCommandAddArg(cmd, '-netdev', ('"user,id=hostnet0,net=169.254.169.0/24,' \
                                                'guestfwd=tcp:169.254.169.254:80-tcp:127.0.0.1:%s"' % metadata_port))
        self.qemuCommandAddArg(cmd, '-device', ('virtio-net-pci,netdev=hostnet0,id=net0,' \
                                                'mac=%s,bus=pci.0,addr=0x3' % mac.attributes['address'].value))

        sysinfo = self.getEl(dom, 'sysinfo')
        sysinfoValue = 'type=1'

        system = self.getEl(sysinfo, 'system')
        systemEntries = self.getEls(system, 'entry')
        for entry in systemEntries:
            sysinfoValue += (',%s=%s' % (entry.attributes['name'].value, entry.childNodes[0].nodeValue))
        self.qemuCommandAddArg(cmd, '-%s' % sysinfo.attributes['type'].value, sysinfoValue.replace(' ', ''))

        self.qemuCommandAddArg(cmd, '-usb', '')

        graphics = self.getEl(devices, 'graphics')
        display, vnc_port = self._next_vnc_display()

        self.qemuCommandAddArg(cmd, '-vnc', '%s:%s' % (graphics.attributes['listen'].value, display))
        self.qemuCommandAddArg(cmd, '-k', graphics.attributes['keymap'].value)
        self.qemuCommandAddArg(cmd, '-vga', 'cirrus')

        self.qemuCommandAddArg(cmd, '-device', 'virtio-balloon-pci,id=balloon0,bus=pci.0,addr=0x5')
        self.qemuCommandAddArg(cmd, '-rtc', 'base=utc,driftfix=slew')
        self.qemuCommandAddArg(cmd, '-no-shutdown', '')

        qmp_port = self._get_ephemeral_port()
        self.qemuCommandAddArg(cmd, '-qmp', 'tcp:127.0.0.1:%s,server,nowait,nodelay' % (qmp_port))

        return (self.qemuCommandStr(cmd), vnc_port, qmp_port, metadata_pid)

    def _start_metadata_proxy(self, instance_id, tenant_id):
        metadata_port = self._get_ephemeral_port()
        current_path = os.path.dirname(__file__)
        python_path = 'python'
        if CONF.python_home is not None:
            python_path = os.path.join(CONF.python_home, 'python')
        proxy_cmd = ('%s %s\metadataproxy.py --instance_id %s --tenant_id %s --metadata_server %s --metadata_port %s '
                     '--metadata_secret "%s" --port %s' % (python_path, current_path, instance_id, tenant_id, CONF.nova_metadata_host, 
                                                           CONF.nova_metadata_port, CONF.nova_metadata_shared_secret, metadata_port))
        LOG.debug('metadataproxy: %s' % proxy_cmd)
        metadata_process = subprocess.Popen(proxy_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return metadata_port, metadata_process.pid

    def _create_instance_metadata_file(self, instance, metadata):
        instance_dir = libvirt_utils.get_instance_path(instance)
        metadata_file_path = os.path.join(instance_dir, INSTANCE_METADATA_FILE)
        with open(metadata_file_path, "w") as metadata_file:
            json.dump(metadata, metadata_file)

    def start_qemu_instance(self, instance):
        cmdline, vnc_port, qmp_port, metadata_pid = self._create_qemu_machine(instance)
        LOG.debug('Cmdline: %s' % (cmdline))
        qemu_process = subprocess.Popen(cmdline)
        metadata = {'pid': qemu_process.pid, 'vnc_port': vnc_port, 'qmp_port': qmp_port, 
                    'metadata_pid': metadata_pid, 'iscsi_devices': {}, 'machine_start_time': int(round(time.time()))}
        self._create_instance_metadata_file(instance, metadata)

    def _next_vnc_display(self):
        port = self._get_available_port(VNC_BASE_PORT, 100)
        display = port - VNC_BASE_PORT
        return (display, port)

    def spawn(self, context, instance, image_meta, injected_files,
              admin_password, network_info=None, block_device_info=None):
        LOG.info("qemuwin.QemuWinDriver creating %s." % instance['name'])
        LOG.info("Instance Data %s." % instance)
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
        
        xml = self.to_xml(context, instance, network_info,
                          disk_info, image_meta,
                          block_device_info=block_device_info,
                          write_to_disk=True)

        self.start_qemu_instance(instance)
    
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

        libvirt_utils.create_image('raw', target,
                                   '%d%c' % (local_size, unit))
        if fs_format:
            utils.mkfs(fs_format, target, label)

    def _create_ephemeral(self, target, ephemeral_size, fs_label, os_type,
                          max_size=None):
        self._create_local(target, ephemeral_size)
        disk.mkfs(os_type, fs_label, target)

    def _get_host_state(self):
        instances_path = CONF.instances_path
        state_file_path = os.path.join(instances_path, 'host_state')
        try:
            with open(state_file_path, 'r') as state_file:
                return json.load(state_file)
        except Exception:
            return self._create_host_state_file()

    def _create_host_state_file(self):
        instances_path = CONF.instances_path
        state_file_path = os.path.join(instances_path, 'host_state')
        host_state = {}
        host_state['uuid'] = self._create_host_uuid()
        host_state['arch'] = self._get_host_arch()
        host_state['next_volume_index'] = 0
        with open(state_file_path, "w") as state_file:
            json.dump({'uuid': host_state['uuid'], 'arch': host_state['arch'], 
                       'next_volume_index': host_state['next_volume_index']}, state_file)

    @staticmethod
    def _get_host_arch():
        arch_bits, os_description = platform.architecture()
        arch = 'i386'
        if arch_bits == '64bit':
            arch = 'x86_64'
        return arch

    def _create_host_uuid(self):
        return str(uuid.uuid1())

    def get_host_capabilities(self):
        """Returns an instance of config.LibvirtConfigCaps representing
           the capabilities of the host.
        """
        # TODO Host UID for Win32?
        # http://libvirt.org/guide/html/Application_Development_Guide-Connections-Capability_Info.html
        # http://blogs.technet.com/b/aaronczechowski/archive/2012/01/04/using-smbios-guid-for-importing-computer-information-for-vmware-guest.aspx
        
        if not self._caps:
            host_state = self._get_host_state()
            self._caps = vconfig.LibvirtConfigCaps()
            self._caps.host = vconfig.LibvirtConfigCapsHost()
            self._caps.host.uuid = host_state['uuid']
            hostcpu = vconfig.LibvirtConfigGuestCPU()
            self._caps.host.cpu = hostcpu
            hostcpu.arch = self._get_host_arch()
            hostcpu.model = 'host-model'
            hostcpu.vendor = 'Intel'
            hostcpu.features = []

        return self._caps

    def get_host_uuid(self):
        """Returns a UUID representing the host."""
        caps = self.get_host_capabilities()
        return caps.host.uuid
    
    def get_host_cpu_for_guest(self):
        """Returns an instance of config.LibvirtConfigGuestCPU
           representing the host's CPU model & topology with
           policy for configuring a guest to match
        """

        caps = self.get_host_capabilities()
        hostcpu = caps.host.cpu
        guestcpu = vconfig.LibvirtConfigGuestCPU()

        guestcpu.model = hostcpu.model
        guestcpu.vendor = hostcpu.vendor
        guestcpu.arch = hostcpu.arch

        guestcpu.match = "exact"

        for hostfeat in hostcpu.features:
            guestfeat = vconfig.LibvirtConfigGuestCPUFeature(hostfeat.name)
            guestfeat.policy = "require"
            guestcpu.features.append(guestfeat)

        return guestcpu

    def get_guest_cpu_config(self):
        mode = CONF.libvirt_cpu_mode
        model = CONF.libvirt_cpu_model

        if mode is None:
            mode = "host-model"
            
        if mode == "none":
            return None

        if mode == "custom" and model is None:
            msg = _("Config requested a custom CPU model, but no "
                    "model name was provided")
            raise exception.Invalid(msg)
        elif mode != "custom" and model is not None:
            msg = _("A CPU model name should not be set when a "
                    "host CPU model is requested")
            raise exception.Invalid(msg)

        LOG.debug(_("CPU mode '%(mode)s' model '%(model)s' was chosen")
                  % {'mode': mode, 'model': (model or "")})

        if mode == "custom":
            cpu = vconfig.LibvirtConfigGuestCPU()
            cpu.model = model
        elif mode == "host-model":
            cpu = self.get_host_cpu_for_guest()
        elif mode == "host-passthrough":
            msg = _("Passthrough of the host CPU was requested but "
                    "this libvirt version does not support this feature")
            raise exception.NovaException(msg)

        return cpu

    def get_hypervisor_type(self):
        """Get hypervisor type.

        :returns: hypervisor type (ex. qemu)

        """
        return HYPERVISOR_TYPE

    def get_hypervisor_version(self):
        """Get hypervisor version.

        :returns: hypervisor version (ex. 12003)

        """
        return HYPERVISOR_VERSION

    def set_cache_mode(self, conf):
        """Set cache mode on LibvirtConfigGuestDisk object."""
        try:
            source_type = conf.source_type
            driver_cache = conf.driver_cache
        except AttributeError:
            return

        cache_mode = self.disk_cachemodes.get(source_type,
                                              driver_cache)
        conf.driver_cache = cache_mode

    def get_guest_disk_config(self, instance, name, disk_mapping, inst_type,
                              image_type=None):
        image = self.image_backend.image(instance,
                                         name,
                                         image_type)
        disk_info = disk_mapping[name]
        return image.libvirt_info(disk_info['bus'],
                                  disk_info['dev'],
                                  disk_info['type'],
                                  self.disk_cachemode,
                                  inst_type['extra_specs'],
                                  self.get_hypervisor_version())

    def get_guest_storage_config(self, instance, image_meta,
                                 disk_info,
                                 rescue, block_device_info,
                                 inst_type):
        devices = []
        disk_mapping = disk_info['mapping']

        block_device_mapping = driver.block_device_info_get_mapping(
            block_device_info)

        if rescue:
            diskrescue = self.get_guest_disk_config(instance,
                                                    'disk.rescue',
                                                    disk_mapping,
                                                    inst_type)
            devices.append(diskrescue)

            diskos = self.get_guest_disk_config(instance,
                                                'disk',
                                                disk_mapping,
                                                inst_type)
            devices.append(diskos)
        else:
            if 'disk' in disk_mapping:
                diskos = self.get_guest_disk_config(instance,
                                                    'disk',
                                                    disk_mapping,
                                                    inst_type)
                devices.append(diskos)

            if 'disk.local' in disk_mapping:
                disklocal = self.get_guest_disk_config(instance,
                                                       'disk.local',
                                                       disk_mapping,
                                                       inst_type)
                devices.append(disklocal)
                self.virtapi.instance_update(
                    nova_context.get_admin_context(), instance['uuid'],
                    {'default_ephemeral_device':
                         block_device.prepend_dev(disklocal.target_dev)})

            for idx, eph in enumerate(
                driver.block_device_info_get_ephemerals(
                    block_device_info)):
                diskeph = self.get_guest_disk_config(
                    instance,
                    blockinfo.get_eph_disk(idx),
                    disk_mapping, inst_type)
                devices.append(diskeph)

            if 'disk.swap' in disk_mapping:
                diskswap = self.get_guest_disk_config(instance,
                                                      'disk.swap',
                                                      disk_mapping,
                                                      inst_type)
                devices.append(diskswap)
                self.virtapi.instance_update(
                    nova_context.get_admin_context(), instance['uuid'],
                    {'default_swap_device': block_device.prepend_dev(
                        diskswap.target_dev)})

            for vol in block_device_mapping:
                connection_info = vol['connection_info']
                vol_dev = block_device.prepend_dev(vol['mount_device'])
                info = disk_mapping[vol_dev]
                cfg = self.volume_driver_method('connect_volume',
                                                connection_info,
                                                info)
                devices.append(cfg)

        if 'disk.config' in disk_mapping:
            diskconfig = self.get_guest_disk_config(instance,
                                                    'disk.config',
                                                    disk_mapping,
                                                    inst_type,
                                                    'raw')
            devices.append(diskconfig)

        for d in devices:
            self.set_cache_mode(d)

        return devices

    def get_guest_config_sysinfo(self, instance):
        sysinfo = vconfig.LibvirtConfigGuestSysinfo()

        sysinfo.system_manufacturer = version.vendor_string()
        sysinfo.system_product = version.product_string()
        sysinfo.system_version = version.version_string_with_package()

        sysinfo.system_serial = self.get_host_uuid()
        sysinfo.system_uuid = instance['uuid']

        return sysinfo

    def get_guest_pci_device(self, pci_device):

        dbsf = pci_utils.parse_address(pci_device['address'])
        dev = vconfig.LibvirtConfigGuestHostdevPCI()
        dev.domain, dev.bus, dev.slot, dev.function = dbsf

        dev.managed = 'yes'

        return dev

    def get_guest_config(self, instance, network_info, image_meta,
                         disk_info, rescue=None, block_device_info=None):
        """Get config data for parameters.

        :param rescue: optional dictionary that should contain the key
            'ramdisk_id' if a ramdisk is needed for the rescue image and
            'kernel_id' if a kernel is needed for the rescue image.
        """

        inst_type = self.virtapi.instance_type_get(
            nova_context.get_admin_context(read_deleted='yes'),
            instance['instance_type_id'])
        inst_path = libvirt_utils.get_instance_path(instance)
        disk_mapping = disk_info['mapping']

        CONSOLE = "console=tty0 console=ttyS0"

        guest = vconfig.LibvirtConfigGuest()
        guest.virt_type = CONF.libvirt_type
        guest.name = instance['name']
        guest.uuid = instance['uuid']
        guest.memory = inst_type['memory_mb'] * 1024
        guest.vcpus = inst_type['vcpus']
        guest.cpuset = CONF.vcpu_pin_set

        quota_items = ['cpu_shares', 'cpu_period', 'cpu_quota']
        for key, value in inst_type['extra_specs'].iteritems():
            scope = key.split(':')
            if len(scope) > 1 and scope[0] == 'quota':
                if scope[1] in quota_items:
                    setattr(guest, scope[1], value)

        guest.cpu = self.get_guest_cpu_config()

        if 'root' in disk_mapping:
            root_device_name = block_device.prepend_dev(
                disk_mapping['root']['dev'])
        else:
            root_device_name = None

        if root_device_name:
            # NOTE(yamahata):
            # for nova.api.ec2.cloud.CloudController.get_metadata()
            self.virtapi.instance_update(
                nova_context.get_admin_context(), instance['uuid'],
                {'root_device_name': root_device_name})

        guest.os_type = vm_mode.get_from_instance(instance)

        if guest.os_type is None:
            guest.os_type = vm_mode.HVM

        LOG.debug('QEMUWINDRIVER: libvirt_type: %s' % (CONF.libvirt_type))
        caps = self.get_host_capabilities()
        if caps.host.cpu.arch in ("i386", "x86_64"):
            LOG.debug('QEMUWINDRIVER: about to run get_guest_config_sysinfo for instance: %s' % (instance))
            guest.sysinfo = self.get_guest_config_sysinfo(instance)
            guest.os_smbios = vconfig.LibvirtConfigGuestSMBIOS()

        guest.os_type = vm_mode.HVM

        if rescue:
            if rescue.get('kernel_id'):
                guest.os_kernel = os.path.join(inst_path, "kernel.rescue")
                guest.os_cmdline = ("root=%s %s" % (root_device_name,
                                                        CONSOLE))

            if rescue.get('ramdisk_id'):
                guest.os_initrd = os.path.join(inst_path, "ramdisk.rescue")
        elif instance['kernel_id']:
            guest.os_kernel = os.path.join(inst_path, "kernel")
            guest.os_cmdline = ("root=%s %s" % (root_device_name,
                                                CONSOLE))
            if instance['ramdisk_id']:
                guest.os_initrd = os.path.join(inst_path, "ramdisk")
        else:
            guest.os_boot_dev = "hd"

        # NOTE(mikal): Microsoft Windows expects the clock to be in
        # "localtime". If the clock is set to UTC, then you can use a
        # registry key to let windows know, but Microsoft says this is
        # buggy in http://support.microsoft.com/kb/2687252
        clk = vconfig.LibvirtConfigGuestClock()
        if instance['os_type'] == 'windows':
            LOG.info(_('Configuring timezone for windows instance to '
                       'localtime'), instance=instance)
            clk.offset = 'localtime'
        else:
            clk.offset = 'utc'
        guest.set_clock(clk)

        # TODO(berrange) One day this should be per-guest
        # OS type configurable
        tmpit = vconfig.LibvirtConfigGuestTimer()
        tmpit.name = "pit"
        tmpit.tickpolicy = "delay"

        tmrtc = vconfig.LibvirtConfigGuestTimer()
        tmrtc.name = "rtc"
        tmrtc.tickpolicy = "catchup"

        clk.add_timer(tmpit)
        clk.add_timer(tmrtc)

        for cfg in self.get_guest_storage_config(instance,
                                                 image_meta,
                                                 disk_info,
                                                 rescue,
                                                 block_device_info,
                                                 inst_type):
            guest.add_device(cfg)

        for vif in network_info:
            cfg = self.vif_driver.get_config(instance,
                                             vif,
                                             image_meta,
                                             inst_type)
            guest.add_device(cfg)

        # The QEMU 'pty' driver throws away any data if no
        # client app is connected. Thus we can't get away
        # with a single type=pty console. Instead we have
        # to configure two separate consoles.
        consolelog = vconfig.LibvirtConfigGuestSerial()
        consolelog.type = "file"
        consolelog.source_path = self._get_console_log_path(instance)
        guest.add_device(consolelog)

        consolepty = vconfig.LibvirtConfigGuestSerial()
        consolepty.type = "pty"
        guest.add_device(consolepty)

        # We want a tablet if VNC is enabled,
        # or SPICE is enabled and the SPICE agent is disabled
        # NB: this implies that if both SPICE + VNC are enabled
        # at the same time, we'll get the tablet whether the
        # SPICE agent is used or not.
        need_usb_tablet = False
        if CONF.vnc_enabled:
            need_usb_tablet = CONF.use_usb_tablet
        elif CONF.spice.enabled and not CONF.spice.agent_enabled:
            need_usb_tablet = CONF.use_usb_tablet

        if need_usb_tablet and guest.os_type == vm_mode.HVM:
            tablet = vconfig.LibvirtConfigGuestInput()
            tablet.type = "tablet"
            tablet.bus = "usb"
            guest.add_device(tablet)

        if CONF.spice.enabled and CONF.spice.agent_enabled:
            channel = vconfig.LibvirtConfigGuestChannel()
            channel.target_name = "com.redhat.spice.0"
            guest.add_device(channel)

        # NB some versions of libvirt support both SPICE and VNC
        # at the same time. We're not trying to second guess which
        # those versions are. We'll just let libvirt report the
        # errors appropriately if the user enables both.

        if CONF.vnc_enabled:
            graphics = vconfig.LibvirtConfigGuestGraphics()
            graphics.type = "vnc"
            graphics.keymap = CONF.vnc_keymap
            graphics.listen = CONF.vncserver_listen
            guest.add_device(graphics)

        if CONF.spice.enabled:
            graphics = vconfig.LibvirtConfigGuestGraphics()
            graphics.type = "spice"
            graphics.keymap = CONF.spice.keymap
            graphics.listen = CONF.spice.server_listen
            guest.add_device(graphics)

        # Qemu guest agent only support 'qemu' and 'kvm' hypervisor
        qga_enabled = False
        # Enable qga only if the 'hw_qemu_guest_agent' property is set
        if (image_meta is not None and image_meta.get('properties') and
                image_meta['properties'].get('hw_qemu_guest_agent')
                is not None):
            hw_qga = image_meta['properties']['hw_qemu_guest_agent']
            if hw_qga.lower() == 'yes':
                LOG.debug(_("Qemu guest agent is enabled through image "
                            "metadata"), instance=instance)
                qga_enabled = True

        if qga_enabled:
            qga = vconfig.LibvirtConfigGuestChannel()
            qga.type = "unix"
            qga.target_name = "org.qemu.guest_agent.0"
            qga.source_path = ("/var/lib/libvirt/qemu/%s.%s.sock" %
                            ("org.qemu.guest_agent.0", instance['name']))
            guest.add_device(qga)

        for pci_dev in pci_manager.get_instance_pci_devs(instance):
            guest.add_device(self.get_guest_pci_device(pci_dev))

        return guest

    def get_guest_pci_device(self, pci_device):

        dbsf = pci_utils.parse_address(pci_device['address'])
        dev = vconfig.LibvirtConfigGuestHostdevPCI()
        dev.domain, dev.bus, dev.slot, dev.function = dbsf

        # only kvm support managed mode
        dev.managed = 'yes'

        return dev

    def to_xml(self, context, instance, network_info, disk_info,
               image_meta=None, rescue=None,
               block_device_info=None, write_to_disk=False):
        # We should get image metadata everytime for generating xml
        if image_meta is None:
            (image_service, image_id) = glance.get_remote_image_service(
                                            context, instance['image_ref'])
            image_meta = compute_utils.get_image_metadata(
                                context, image_service, image_id, instance)
        # NOTE(danms): Stringifying a NetworkInfo will take a lock. Do
        # this ahead of time so that we don't acquire it while also
        # holding the logging lock.
        network_info_str = str(network_info)
        LOG.debug(_('Start to_xml '
                    'network_info=%(network_info)s '
                    'disk_info=%(disk_info)s '
                    'image_meta=%(image_meta)s rescue=%(rescue)s'
                    'block_device_info=%(block_device_info)s'),
                  {'network_info': network_info_str, 'disk_info': disk_info,
                   'image_meta': image_meta, 'rescue': rescue,
                   'block_device_info': block_device_info})
        conf = self.get_guest_config(instance, network_info, image_meta,
                                     disk_info, rescue, block_device_info)
        xml = conf.to_xml()

        if write_to_disk:
            instance_dir = libvirt_utils.get_instance_path(instance)
            xml_path = os.path.join(instance_dir, 'libvirt.xml')
            libvirt_utils.write_to_file(xml_path, xml)

        LOG.debug(_('End to_xml instance=%(instance)s xml=%(xml)s'),
                  {'instance': instance, 'xml': xml})
        return xml

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
        if not (self._instance_exists(instance)):
            raise exception.InstanceNotRunning(instance_id=instance['uuid'])
        update_task_state(task_state=task_states.IMAGE_UPLOADING)

    def snapshot(self, context, instance, name, update_task_state):
        if not (self._instance_exists(instance)):
            raise exception.InstanceNotRunning(instance_id=instance['uuid'])
        update_task_state(task_state=task_states.IMAGE_UPLOADING)

    @staticmethod
    def _get_ephemeral_port():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
            sock.close()
            return port
        except Exception:
            return None

    @staticmethod
    def _get_available_port(initial_port, max_tries):
        for port in xrange(initial_port, initial_port + max_tries):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                result = sock.connect_ex(('127.0.0.1', port))
                sock.close()
                if result == SOCKET_NOT_BOUND:
                    return port
            except Exception:
                pass
        return None

    def _get_qmp_connection(self, instance):
        try:
            state = self._get_instance_metadata(instance)
            if (state is not None):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect(('127.0.0.1', state['qmp_port']))
                return s
        except Exception, e:
            pass
        return None

    def _run_qmp_command(self, instance, command, arguments=None, suppressOutput=False):
        LOG.debug('QEMUWINDRIVER: Running QMP command %s on instance %s' % (command, instance['name']))
        s = self._get_qmp_connection(instance)
        if s is not None:
            s.sendall('{"execute": "qmp_capabilities"}')
            time.sleep(QMP_CAPABILITY_WAIT)
            capabilitiesOuput = s.recv(1024)
            if arguments is not None:
                qmp_command = '{"execute": "%s", "arguments": %s}' % (command, arguments)
                LOG.debug('QEMUWINDRIVER: running qmp command %s' % (qmp_command))
                s.sendall(qmp_command)
            else:
                qmp_command = '{"execute": "%s"}' % (command)
                LOG.debug('QEMUWINDRIVER: running qmp command %s' % (qmp_command))
                s.sendall(qmp_command)
            commandOuput = None
            if not suppressOutput:
                commandOuput = s.recv(1024)
                LOG.debug('QEMUWINDRIVER: QMP command output: %s' % (commandOuput))
            s.close()
            return commandOuput
        else:
            LOG.debug('QEMUWINDRIVER: Could not run QMP command because socket failed')
            return None

    def _get_qmp_instance_status(self, instance):
        json_string = self._run_qmp_command(instance, QMP_MACHINE_STATUS)
        is_running = False
        status = None
        if json_string is not None:
            machine_status = json.loads(json_string)            
            # returns two fields (running, status)
            # running is boolean, true if running or false if not
            # status is a string with values like running, paused, shutdown
            is_running = machine_status['return']['running']
            status = machine_status['return']['status']
        else :
            state = self._get_instance_metadata(instance)
            if (state is not None and 'expected_state' in state):
                if (state['expected_state'] == 'running'):
                    status = 'internal-error'
                elif (state['expected_state'] == 'shutdown'):
                    status = 'shutdown'
        return (is_running, status)

    def reboot(self, context, instance, network_info, reboot_type,
               block_device_info=None, bad_volumes_callback=None):
        self._run_qmp_command(instance, QMP_REBOOT_COMMAND)
        return True

    @staticmethod
    def get_host_ip_addr():
        return socket.gethostbyname(socket.gethostname())

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
        running, status = self._get_qmp_instance_status(instance)
        if running:
            self._run_qmp_command(instance, QMP_SHUTDOWN_COMMAND)
            running, current_status = self._get_qmp_instance_status(instance)
            remaining_retries = POWEROFF_RETRIES
            while (current_status != 'shutdown') and (remaining_retries > 0):
                time.sleep(POWEROFF_RETRY_INTERVAL)
                running, current_status = self._get_qmp_instance_status(instance)
                remaining_retries -= 1
            self._run_qmp_command(instance, QMP_STOP_COMMAND, suppressOutput=True)
            state = self._get_instance_metadata(instance)
            if state is not None:
                state['expected_state'] = 'shutdown'
                self._create_instance_metadata_file(instance, state)

    def power_on(self, context, instance, network_info, block_device_info):
        state = self._get_instance_metadata(instance)
        if state is not None:
            cmdline, vnc_port, qmp_port = self._create_qemu_machine(instance)
            qemu_process = subprocess.Popen(cmdline)
            state['pid'] = qemu_process.pid
            state['qmp_port'] = qmp_port
            state['vnc_port'] = vnc_port
            state['expected_state'] = 'running'
            if 'iscsi_devices' not in state:
                state['iscsi_devices'] = {}
            self._create_instance_metadata_file(instance, state)

    def soft_delete(self, instance):
        pass

    def restore(self, instance):
        pass

    def pause(self, instance):
        self._run_qmp_command(instance, QMP_SUSPEND_COMMAND)

    def unpause(self, instance):
        self._run_qmp_command(instance, QMP_RESUME_COMMAND)

    def suspend(self, instance):
        LOG.debug('QEMUWINDRIVER suspending instance %s' % (instance['name']))
        self._run_qmp_command(instance, QMP_SUSPEND_COMMAND)

    def resume(self, context, instance, network_info, block_device_info=None):
        LOG.debug('QEMUWINDRIVER resuming instance %s' % (instance['name']))
        self._run_qmp_command(instance, QMP_RESUME_COMMAND)


#TODO: This without the instance (maybe getting the name and searching the instance dir?)
    def _get_instance_metadata(self, instance):
        instance_dir = libvirt_utils.get_instance_path(instance)
        metadata_file_path = os.path.join(instance_dir, INSTANCE_METADATA_FILE)
        try:
            with open(metadata_file_path, 'r') as metadata_file:
                return json.load(metadata_file)
        except Exception:
            return None
    
    def destroy(self, instance, network_info, block_device_info=None,
                destroy_disks=True, context=None):

        def _kill(pid):
            handle = ctypes.windll.kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
            ctypes.windll.kernel32.TerminateProcess(handle, -1)
            ctypes.windll.kernel32.CloseHandle(handle)
            time.sleep(5)

        metadata = self._get_instance_metadata(instance)
        if (metadata is not None):
            _kill(metadata['pid'])
            _kill(metadata['metadata_pid'])
        shutil.rmtree(libvirt_utils.get_instance_path(instance), True)

    def _execute_iscsi_command(self, cmd, arguments=False):
        iscsi_cmd = '%s %s' % (ISCSI_CLI, cmd)
        if arguments:
            iscsi_cmd += (' %s' % arguments)
        p = subprocess.Popen(iscsi_cmd, stdout=subprocess.PIPE)
        out, err = p.communicate()
        return (out, err)

    def _list_targets(self):
        out, err = self._execute_iscsi_command(ISCSI_LIST_TARGETS_CMD)
        lines = out.splitlines()
        target_list = []
        list_started_string = 'Targets List:'
        list_started = False
        for line in lines:
            raw_line = line.strip()
            if raw_line == ISCSI_COMMAND_END_MESSAGE:
                break
            if list_started:
                target_list.append(raw_line)
            if raw_line == list_started_string:
                list_started = True
        return target_list

    def _add_target_portal(self, portal_address):
        out, err = self._execute_iscsi_command(ISCSI_ADD_TARGET_PORTAL_CMD, portal_address)

    def _login_target(self, target):
        out, err = self._execute_iscsi_command(ISCSI_LOGIN_CMD, target)

    def _logout_target(self, session_id):
        out, err = self._execute_iscsi_command(ISCSI_LOGOUT_CMD, session_id)

    def _connected_targets(self):
        out, err = self._execute_iscsi_command(ISCSI_TARGET_MAPPINGS_CMD)
        lines = out.splitlines()
        is_target_data = False
        mappings = []
        target = {}
        for line in lines:
            clean_line = line.strip()
            if clean_line.startswith('Session Id'):
                is_target_data = True
            if clean_line.startswith('Target Lun:') and is_target_data:
                is_target_data = False
                mappings.append(target)
                target = {}
            if is_target_data:
                line_data = clean_line.split(' : ')
                target[line_data[0].strip()] = line_data[1].strip()
        return mappings

    def _get_physical_drive(self, target):
        out, err = self._execute_iscsi_command(ISCSI_LIST_SESSIONS_CMD)
        lines = out.splitlines()
        is_disk_device = False
        is_target = False
        for line in lines:
            clean_line = line.strip()
            if clean_line.startswith('Target Name'):
                line_data = clean_line.split(' : ')
                if line_data[1].strip() == target:
                    is_target = True
                else:
                    is_target = False
            if clean_line.startswith('Device Type'):
                line_data = clean_line.split(' : ')
                if line_data[1].strip() == 'Disk':
                    is_disk_device = True
                else:
                    is_disk_device = False
            if is_disk_device and is_target and clean_line.startswith('Legacy Device Name'):
                line_data = clean_line.split(' : ')
                return line_data[1].strip()

    def _get_iscsi_session_id(self, target):
        out, err = self._execute_iscsi_command(ISCSI_LIST_SESSIONS_CMD)
        lines = out.splitlines()
        is_disk_device = False
        is_target = False
        session_id = None
        for line in lines:
            clean_line = line.strip()
            if clean_line.startswith('Session Id'):
                line_data = clean_line.split(' : ')
                session_id = line_data[1]
            if clean_line.startswith('Target Name'):
                line_data = clean_line.split(' : ')
                if (line_data[1].strip() == target) and (session_id is not None):
                    return session_id
        return None

    def _get_initiator_name(self):
        out, err = self._execute_iscsi_command(ISCSI_LIST_SESSIONS_CMD)
        lines = out.splitlines()
        for line in lines:
            clean_line = line.strip()
            if clean_line.startswith('Initiator Node Name'):
                line_data = clean_line.split(' : ')
                return line_data[1]
        return None

    def _run_qmp_human_monitor_command(self, instance, command):
        return self._run_qmp_command(instance, QMP_HUMAN_MONITOR_COMMAND, '{"%s": "%s"}' % (QMP_COMMAND_LINE, command))

    def _attach_volume(self, connection_info, instance, mountpoint):
        LOG.debug('QEMUWINDRIVER: volume connection info %s and mountpoint %s' % (connection_info, mountpoint))

        target_portal_address = connection_info['data']['target_portal'].split(':')
        self._add_target_portal(target_portal_address[0])
        self._login_target(connection_info['data']['target_iqn'])

        physical_drive = self._get_physical_drive(connection_info['data']['target_iqn'])
        if physical_drive is None:
            return False
        physical_drive = physical_drive.replace("\\", "\\\\")
        LOG.debug('QEMUWINDRIVER: volume connection physical drive %s' % (physical_drive))

        instance_metadata = self._get_instance_metadata(instance)
        LOG.debug('QEMUWINDRIVER: attach new volume with instance_metadata %s' % (instance_metadata))
        next_volume_index = 0
        next_drive_add_index = 10
        while True:
            LOG.debug('QEMUWINDRIVER: attach new volume index exists? %s' % (next_volume_index not in instance_metadata['iscsi_devices']))
            if str(next_volume_index) not in instance_metadata['iscsi_devices']:
                break
            next_volume_index += 1
            next_drive_add_index += 1
            LOG.debug('QEMUWINDRIVER: attach new volume incrementing next_volume_index %s and next_drive_add_index %s' % (next_volume_index, next_drive_add_index))

        drive_id = 'drive-scsi0-0-0-%s' % (next_volume_index)
        device_id = 'scsi0-0-0-%s' % (next_volume_index)
        drive_add = 'drive_add %s file=%s,if=none,id=%s' % (next_drive_add_index, physical_drive, drive_id)
        device_add = 'device_add virtio-blk-pci,drive=%s,id=%s' % (drive_id, device_id)
        LOG.debug('QEMUWINDRIVER: attach new volume on index %s and driveid %s and deviceid %s' % (next_volume_index, drive_id, device_id))

        def _check_qmp_result(json_result, expected):
            if 'return' not in json_result:
                return False
            elif json_result['return'].strip() not in expected:
                return False
            return True

        result_drive_add = self._run_qmp_human_monitor_command(instance, drive_add)
        LOG.debug('QEMUWINDRIVER: new volume drive add result %s' % (result_drive_add))
        json_result_drive_add = json.loads(result_drive_add)
        if _check_qmp_result(json_result_drive_add, ['OK']):
            result_device_add = self._run_qmp_human_monitor_command(instance, device_add)
            LOG.debug('QEMUWINDRIVER: new volume device add result %s' % (result_device_add))
            json_result_device_add = json.loads(result_device_add)
            if not _check_qmp_result(json_result_device_add, ['OK', '']):
                return False
        else:
            return False

        instance_metadata['iscsi_devices'][next_volume_index] = connection_info['data']['target_iqn']
        self._create_instance_metadata_file(instance, instance_metadata)
        return True

    def attach_volume(self, context, connection_info, instance, mountpoint,
                      encryption=None):
        """Attach the disk to the instance at mountpoint using info."""
        return self._attach_volume(connection_info, instance, mountpoint)

    def detach_volume(self, connection_info, instance, mountpoint,
                      encryption=None):
        """Detach the disk attached to the instance."""
        try:
            instance_metadata = self._get_instance_metadata(instance)
            remove_index = None
            if 'iscsi_devices' in instance_metadata:
                for index in instance_metadata['iscsi_devices']:
                    if instance_metadata['iscsi_devices'][index] == connection_info['data']['target_iqn']:
                        remove_index = index
                        drive_id = 'drive-scsi0-0-0-%s' % (index)
                        device_id = 'scsi0-0-0-%s' % (index)
                        drive_del = 'drive_del %s' % (drive_id)
                        device_del = 'device_del %s' % (device_id)
                        result_device_del = self._run_qmp_human_monitor_command(instance, device_del)
                        break
                del instance_metadata['iscsi_devices'][remove_index]
                self._create_instance_metadata_file(instance, instance_metadata)

            session_id = self._get_iscsi_session_id(connection_info['data']['target_iqn'])
            if session_id is not None:
                self._logout_target(session_id)
        except KeyError:
            pass
        return True

    def swap_volume(self, old_connection_info, new_connection_info,
                    instance, mountpoint):
        """Replace the disk attached to the instance."""
        is_detached = self.detach_volume(old_connection_info, instance, mountpoint)
        if is_detached:
            return self._attach_volume(new_connection_info, instance, mountpoint)
        return False

    def attach_interface(self, instance, image_meta, vif):
        pass

    def detach_interface(self, instance, vif):
        pass

    def _get_power_state(self, instance):
      is_running, qmp_status = self._get_qmp_instance_status(instance)
      if (qmp_status is None):
          return power_state.NOSTATE
      if (qmp_status in ['running', 'debug']):
          return power_state.RUNNING
      if (qmp_status in ['inmigrate', 'io-error', 'paused', 'postmigrate', 'prelaunch', 'finish-migrate', 'restore-vm', 'watchdog', 'save-vm']):
          return power_state.PAUSED
      if (qmp_status == 'shutdown'):
          return power_state.SHUTDOWN
      if (qmp_status == 'internal-error'):
          return power_state.CRASHED
      return power_state.NOSTATE

    def _instance_exists(self, instance):
      list_of_instances = self.list_instances()
      return instance['uuid'] in list_of_instances

    def get_info(self, instance):
        if not(self._instance_exists(instance)):
            raise exception.InstanceNotFound(instance_id=instance['name'])
        instance_power_state = self._get_power_state(instance)
        instance_metadata = self._get_instance_metadata(instance)
        cputime = (int(round(time.time())) - int(instance_metadata['machine_start_time']))*(10**6)
        result_cpus = self._run_qmp_command(instance, QMP_QUERY_CPUS)
        num_cpu = 0
        if (result_cpus is not None):
            num_cpu = len(json.loads(result_cpus))
        return {'state': instance_power_state,
                'max_mem': 0,
                'mem': 0,
                'num_cpu': num_cpu,
                'cpu_time': cputime}

    def _get_value(entry):
        values = entry.split("=")
        return values[1]

    def get_diagnostics(self, instance):
        if not(self._instance_exists(instance)):
            raise exception.InstanceNotFound(instance_id=instance['name'])
        result_blockstats = self._run_qmp_human_monitor_command(instance, "info blockstats")
        json_blockstats = json.loads(result_blockstats)
        diagnostics = {}
        for block_device_line in json_blockstats['return'].split("\n"):
            if (block_device_line.strip() != ''):
                block_device_info = block_device_line.split()
                guest_disk = block_device_info[0].strip(':') 
                diagnostics[guest_disk + "_read_req"] = _get_value(block_device_info[1])
                diagnostics[guest_disk + "_read"] = _get_value(block_device_info[2])
                diagnostics[guest_disk + "_write_req"] = _get_value(block_device_info[3])
                diagnostics[guest_disk + "_write"] = _get_value(block_device_info[4])
                diagnostics[guest_disk + "_errors"] = _get_value(block_device_info[5])
        return diagnostics

    def get_all_bw_counters(self, instances):
        """Return bandwidth usage counters for each interface on each
           running VM.
        """
        bw = []
        return bw

    def interface_stats(self, instance_name, iface_id):
        return [0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L]

    @staticmethod
    def _get_xml_desc(instance):
        xmlpath = os.path.join(libvirt_utils.get_instance_path(instance),
                            'libvirt.xml')
        with open(xmlpath, "r") as xmlfile:
            return xmlfile.read()

    def get_console_output(self, instance):
        path = self._get_console_log_path(instance)
        if not path:
            msg = _("Guest does not have a console available")
            raise exception.NovaException(msg)
       
        with libvirt_utils.file_open(path, 'rb') as fp:
            log_data, remaining = utils.last_bytes(fp,
                                                   MAX_CONSOLE_BYTES)
            if remaining > 0:
                LOG.info(_('Truncated console log returned, %d bytes '
                           'ignored'), remaining, instance=instance)
            return log_data

    def get_vnc_console(self, instance):
        state = self._get_instance_metadata(instance)
        port = state['vnc_port']
        host = CONF.vncserver_proxyclient_address
        return {'host': host, 'port': port, 'internal_access_path': None}

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

    def _get_host_disk_space(self):
        drive = unicode(os.getenv("SystemDrive"))
        freeuser = ctypes.c_int64()
        total = ctypes.c_int64()
        free = ctypes.c_int64()
        ctypes.windll.kernel32.GetDiskFreeSpaceExW(drive, 
            ctypes.byref(freeuser), 
            ctypes.byref(total), 
            ctypes.byref(free))
        return (freeuser.value, total.value)


    def _get_host_disk_total(self):
        free, total = self._get_host_disk_space()
        return total

    def _get_host_disk_free(self):
        free, total = self._get_host_disk_space()
        return free

    def _get_host_disk_used(self):
        free, total = self._get_host_disk_space()
        return total - free

    def _get_host_ram(self):
        c_ulonglong = ctypes.c_ulonglong
        class MEMORYSTATUS(ctypes.Structure):
            _fields_ = [
                ('dwLength', c_ulonglong),
                ('dwMemoryLoad', c_ulonglong),
                ('dwTotalPhys', c_ulonglong),
                ('dwAvailPhys', c_ulonglong),
                ('dwTotalPageFile', c_ulonglong),
                ('dwAvailPageFile', c_ulonglong),
                ('dwTotalVirtual', c_ulonglong),
                ('dwAvailVirtual', c_ulonglong)
            ]
        memoryStatus = MEMORYSTATUS()
        memoryStatus.dwLength = ctypes.sizeof(MEMORYSTATUS)
        ctypes.windll.kernel32.GlobalMemoryStatus(ctypes.byref(memoryStatus))
        mem = memoryStatus.dwTotalPhys
        availRam = memoryStatus.dwAvailPhys
        return (mem, availRam)

    def _get_host_free_ram(self):
        comp = wmi.WMI()
        free_ram = 0
        for os in comp.Win32_OperatingSystem():
            free_ram += int(os.FreePhysicalMemory)
        return free_ram

    def _get_host_total_ram(self):
        comp = wmi.WMI()
        total = 0
        for i in comp.Win32_ComputerSystem():
            total += int(i.TotalPhysicalMemory)
        return total

    def _get_host_used_ram(self):
        total = self._get_host_total_ram()
        free = self._get_host_free_ram()
        LOG.debug("QEMUWINDRIVER: free memory %s" % (free))
        return total - free

    def get_available_resource(self, nodename):
        """Updates compute manager resource info on ComputeNode table.

           Since we don't have a real hypervisor, pretend we have lots of
           disk and ram.
        """
        if nodename not in _NODES:
            return {}

        local_gb = self._get_host_disk_total() / (1024 ** 3)
        local_gb_used = self._get_host_disk_used() / (1024 ** 3)
        memory_mb = self._get_host_total_ram() / (1024 ** 2)
        memory_mb_used = self._get_host_used_ram() / (1024 ** 2)

        disk_available_least = self.get_disk_available_least()

        LOG.debug('QEMUWINDRIVER: total memory %s, used memory %s' % (memory_mb, memory_mb_used))
        LOG.debug('QEMUWINDRIVER: Disk available least GB: %s' % (disk_available_least))

        dic = {'vcpus': 1,
               'memory_mb': memory_mb,
               'local_gb': local_gb,
               'vcpus_used': 0,
               'memory_mb_used': memory_mb_used,
               'local_gb_used': local_gb_used,
               'hypervisor_type': HYPERVISOR_TYPE,
               'hypervisor_version': HYPERVISOR_VERSION,
               'hypervisor_hostname': nodename,
               'disk_available_least': disk_available_least,
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

    def get_host_stats(self, refresh=False):
        """Return fake Host Status of ram, disk, network."""
        stats = []
        for nodename in _NODES:
            host_status = self.get_available_resource(nodename)
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
        instances_path = CONF.instances_path
        instances = self.list_instances()
        LOG.debug('QEMUWINDRIVER: machines now: %s' % (instances))
        disk_available_least = 0
        try:
            for instance in instances:
                disk_path = os.path.join(instances_path, instance, 'disk')
                qemuImgInfoOut = images.qemu_img_info(disk_path)
                disk_over_commit = qemuImgInfoOut.virtual_size - int(os.path.getsize(disk_path))
                disk_available_least += (self._get_host_disk_free() - disk_over_commit) / (1024 ** 3)
        except Exception:
            pass
        
        return disk_available_least

    def add_to_aggregate(self, context, aggregate, host, **kwargs):
        pass

    def remove_from_aggregate(self, context, aggregate, host, **kwargs):
        pass

    def get_volume_connector(self, instance):
        host_ip = self.get_host_ip_addr()
        hostname = socket.gethostname()
        connector = {'ip': host_ip, 
                     'host': CONF.host}
        initiator_name = self._get_initiator_name()
        if initiator_name is not None:
            connector['initiator'] = initiator_name
        return connector

    def get_available_nodes(self, refresh=False):
        return _NODES

    def instance_on_disk(self, instance):
        instance_path = os.path.join(CONF.instances_path, instance['uuid'])
        return os.access(instance_path, OS.W_OK)

    def list_instance_uuids(self):
        return self.list_instances()
