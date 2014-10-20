from driver import QemuWinDriver
import mock
import unittest
import random
import os
import time
import shutil
import sys

reload(sys)
sys.setdefaultencoding("UTF8")

INSTANCE_TEST_PATH = 'C:\\iunittest\\'
instance_tracker = [];
class QemuWinDriverTestCase(unittest.TestCase):



  maxDiff = None
   
  @mock.patch('driver.CONF')
  @mock.patch('driver.QemuWinDriver.__init__',mock.Mock(return_value=None))
  def test_list_instance(self, mock_conf):
    # set up the mock
    qemuwindriver = QemuWinDriver()
    mock_conf.instances_path = INSTANCE_TEST_PATH
    
    #resets the test environment
    self.reset_test_environ()
    #creating two fake instances

    self.add_fake_instances()
    time.sleep(1)
    self.add_fake_instances()

    #calling the testes method

    listinstances = qemuwindriver.list_instances()

    #comparing method return to stored information

    self.assertItemsEqual(instance_tracker, listinstances)

    #comparing number of instances to expected number

    assert len(listinstances) == 2

    #removing a fake instance

    self.remove_fake_instance()

    listinstances = qemuwindriver.list_instances()

    self.assertItemsEqual(instance_tracker, listinstances)

    assert len(listinstances) == 1

    self.remove_fake_instance()

    listinstances = qemuwindriver.list_instances()

    #Expects a empty list if there are no instances

    self.assertItemsEqual([], listinstances)

    assert len(listinstances) == 0


  def add_fake_instances(self):
    #creates a unique tag to be part of the name
    tag = str(time.time())
    instance_path = (os.path.join(INSTANCE_TEST_PATH, tag))
    os.mkdir(instance_path)
    #creates the necessary metadata file
    metadata_file_path = os.path.join(instance_path, 'metadata')
    metadata_file = open(metadata_file_path, 'w')
    metadata_file.write('Useful Information')
    metadata_file.close
    
    #adds the fake instance name to a list so we can track it
    instance_tracker.append(tag);

  def remove_fake_instance(self, index=0):
    tag = instance_tracker[index]
    instance_path = (os.path.join(INSTANCE_TEST_PATH, tag))
    shutil.rmtree(instance_path, ignore_errors=True)
    instance_tracker.remove(tag)

  def reset_test_environ(self):
    for f in os.listdir(INSTANCE_TEST_PATH):
      shutil.rmtree(f, ignore_errors=True)  


  @mock.patch('driver.CONF')
  @mock.patch('driver.QemuWinDriver.__init__',mock.Mock(return_value=None))
  @mock.patch('driver.QemuWinDriver._supports_direct_io', mock.Mock(side_effect=[False, True]))
  def test_disk_cache_mode(self, mock_conf):
    qemuwindriver = QemuWinDriver()
    mock_conf.instances_path = None

    qemuwindriver._disk_cachemode = None
 #   mock_supp.return_value = False
    cachemode = qemuwindriver.disk_cachemode
    self.assertEqual(cachemode, "writethrough")

    qemuwindriver._disk_cachemode = None
    cachemode = qemuwindriver.disk_cachemode
    self.assertEqual(cachemode, 'none')

    qemuwindriver._disk_cachemode = 'none'
    cachemode = qemuwindriver.disk_cachemode
    self.assertEqual(cachemode ,'none')

  @mock.patch('driver.CONF')
  @mock.patch('driver.QemuWinDriver.__init__',mock.Mock(return_value=None))
  @mock.patch('driver.os')
  @mock.patch('driver.os.path')
  def test_supports_direct_io(self, mock_conf, mock_os, mock_path):
    dirpath = INSTANCE_TEST_PATH
    mock_os.open.return_value = None
    mock_os.close.return_value = False   
    direct_io = QemuWinDriver._supports_direct_io(dirpath)
    assert direct_io 
  
  @mock.patch('driver.CONF')
  @mock.patch('driver.QemuWinDriver.__init__',mock.Mock(return_value=None))
  @mock.patch('driver.minidom')
  def test_getEl(self, mock_conf, mock_minidom):
    qemuwindriver = QemuWinDriver()
    elName = 'cpu'
    fakevalue = 'fakevalue'
    mock_minidom.getElementsByTagName.return_value = [fakevalue]
    element = qemuwindriver.getEl(mock_minidom, elName)
    self.assertEqual(element, fakevalue)
    mock_minidom.getElementsByTagName.return_value = []
    self.assertRaises(IndexError, qemuwindriver.getEl, mock_minidom, elName)

  
  @mock.patch('driver.CONF')
  @mock.patch('driver.QemuWinDriver.__init__',mock.Mock(return_value=None))
  @mock.patch('driver.minidom')
  def test_getEls(self, mock_conf, mock_minidom):
    qemuwindriver = QemuWinDriver()
    elName = 'cpu'
    fakevalue = 'fakevalue'
    mock_minidom.getElementsByTagName.return_value = [fakevalue]
    element = qemuwindriver.getEls(mock_minidom, elName)
    self.assertEqual(element, [fakevalue])
    mock_minidom.getElementsByTagName.return_value = []
    element = qemuwindriver.getEls(mock_minidom, elName)
    self.assertEqual(element, [])

  @mock.patch('driver.CONF')
  @mock.patch('driver.QemuWinDriver.__init__', mock.Mock(return_value=None))
  def test_qemuCommandNew(self, mock_conf):
    qemuwindriver = QemuWinDriver()
    mock_conf.qemu_home = INSTANCE_TEST_PATH
    arch = 'x64'
    qemu_command = qemuwindriver.qemuCommandNew(arch)
    qemu_command_expected = ['"%s"' % os.path.join(INSTANCE_TEST_PATH, 'qemu-system-x64.exe')]
    self.assertEqual(qemu_command, qemu_command_expected)
    mock_conf.qemu_home = None
    arch = 'x86'
    qemu_command = qemuwindriver.qemuCommandNew(arch)
    qemu_command_expected = ['qemu-system-x86.exe']
    self.assertEqual(qemu_command, qemu_command_expected)

  @mock.patch('driver.CONF')
  @mock.patch('driver.QemuWinDriver.__init__', mock.Mock(return_value=None))
  def test_qemuCommandAddArg(self, mock_conf):
    qemuwindriver = QemuWinDriver()
    command = ['fakecommand']
    arg = 'fakearg'
    val = 'fakevalue'
    qemuwindriver.qemuCommandAddArg(command, arg, val)
    expected_command = ['fakecommand', arg, val]
    self.assertEqual(command, expected_command)

  @mock.patch('driver.CONF')
  @mock.patch('driver.QemuWinDriver.__init__', mock.Mock(return_value=None))
  def test_qemuCommandStr(self, mock_conf):
    qemuwindriver = QemuWinDriver()
    command = ['fakecommand', 'fakearg', 'fakevalue']
    command_str = qemuwindriver.qemuCommandStr(command)
    command_str_expected = 'fakecommand fakearg fakevalue'
    self.assertEqual(command_str, command_str_expected)
    command = ['fakecommand']
    command_str = qemuwindriver.qemuCommandStr(command)
    command_str_expected = 'fakecommand'
    self.assertEqual(command_str, command_str_expected)

  @mock.patch('driver.CONF', mock.Mock(qemu_home = INSTANCE_TEST_PATH))
  @mock.patch('driver.QemuWinDriver.__init__', mock.Mock(return_value=None))
  @mock.patch('driver.QemuWinDriver.getText', mock.Mock(side_effect= ['fakearch', '1024', 'fakename', 'fakeuuid', 'fakevcpu']))
  @mock.patch('driver.QemuWinDriver.getEl', mock.Mock(side_effect=  ['fakecpu', ['fakedevice1', 'fakedevice2'], 'fakedisk' , mock.Mock(attributes = {"file":mock.Mock(value='fakefile')}),
                            'fakeserial', mock.Mock(attributes = {"path":mock.Mock( value='fakepath')}), 'fakeinterface', mock.Mock(attributes = {"address":mock.Mock(value='fakeaddress')}),
                            mock.Mock(attributes= {"type":mock.Mock(value = 'faketype')}), 'fakesystem', mock.Mock(attributes = {'keymap': mock.Mock(value = 'fakekeymap'), 'listen': mock.Mock(value = 'fakelisten')})]))
  @mock.patch('driver.QemuWinDriver.getEls',mock.Mock(side_effect=[[mock.Mock(attributes = {"name":mock.Mock(value = 'fakename')}, childNodes = [mock.Mock(nodeValue='fakevalue')])]]))
  @mock.patch('driver.QemuWinDriver._get_instance_path', mock.Mock(return_value=INSTANCE_TEST_PATH))
  @mock.patch('driver.minidom')
  @mock.patch('driver.QemuWinDriver._next_vnc_display', mock.Mock(return_value=('fakedisplay', 'fakeport')))
  @mock.patch('driver.QemuWinDriver._get_ephemeral_port', mock.Mock(return_value= 'fakeephemeralport'))  
  @mock.patch('driver.QemuWinDriver.qemuCommandNew', mock.Mock(return_value=['%s%s'  % (INSTANCE_TEST_PATH, 'qemu-system-i386')]))
  def test_create_qemu_machine(self, mock_minidom):
    qemuwindriver = QemuWinDriver()
    diskSource = mock.Mock(attributes ={"file":'fakefile'})
    mock_minidom.parse.return_value = mock.Mock()
    seriaSource = mock.Mock(attributes = {"path":'fakepath'})
    mac = mock.Mock(attributes = {'address':'fakeaddress'})
    sysinfo = mock.Mock(attributes= {'type':'faketype'} )
    graphics = mock.Mock(attributes ={'keymap':'fakekeymap', 'type':'fakegraphictype', 'listen':'fakelistenvalue'})
    metadata_port = 'fakeport'
    metadata_pid = 'fakepid'
    instance = "fakeinstance"
#    expected_command = 'C:\iunittest\qemu-system-i386 -m 1 -smp 1,sockets=1,cores=1,threads=1'  \
#                       ' -name fakename -uuid fakeuuid -drive "file=fakefile,id=drive-virtio-disk0,if=none"' \
#                       ' -device virtio-blk-pci,bus=pci.0,addr=0x4,drive=drive-virtio-disk0,id=virtio-disk0,bootindex=1' \
#                       ' -chardev "file,id=charserial0,path=fakepath" -device isa-serial,chardev=charserial0,id=serial0' \
#                       ' -netdev "user,id=hostnet0,net=169.254.169.0/24,guestfwd=tcp:169.254.169.254:80-tcp:127.0.0.1:fakeport"' \
#                       ' -device virtio-net-pci,netdev=hostnet0,id=net0,mac=fakeaddress,bus=pci.0,addr=0x3' \
#                       ' -faketype type=1,fakename=fakevalue -usb  -vnc fakelisten:fakedisplay -k "C:\iunittest\keymaps\fakekeymap" -vga cirrus -device' \
#                       ' virtio-balloon-pci,id=balloon0,bus=pci.0,addr=0x5 -rtc base=utc,driftfix=slew' \
#                       ' -no-shutdown  -qmp tcp:127.0.0.1:fakeephemeralport,server,nowait '
    mount_command = ['%s%s' % (INSTANCE_TEST_PATH, 'qemu-system-i386')]
    mount_command.append('-m')
    mount_command.append('1')
    mount_command.append('-smp')
    mount_command.append('1,sockets=1,cores=1,threads=1')
    mount_command.append('-name')
    mount_command.append('fakename')
    mount_command.append('-uuid')
    mount_command.append('fakeuuid')
    mount_command.append('-drive')
    mount_command.append('"file=fakefile,id=drive-virtio-disk0,if=none"')
    mount_command.append('-device')
    mount_command.append('virtio-blk-pci,bus=pci.0,addr=0x4,drive=drive-virtio-disk0,id=virtio-disk0,bootindex=1')
    mount_command.append('-chardev')
    mount_command.append('"file,id=charserial0,path=fakepath"')
    mount_command.append('-device')
    mount_command.append('isa-serial,chardev=charserial0,id=serial0')
    mount_command.append('-netdev')
    mount_command.append('"user,id=hostnet0,net=169.254.169.0/24,guestfwd=tcp:169.254.169.254:80-tcp:127.0.0.1:fakeport"')
    mount_command.append('-device')
    mount_command.append('virtio-net-pci,netdev=hostnet0,id=net0,mac=fakeaddress,bus=pci.0,addr=0x3')
    mount_command.append('-faketype')
    mount_command.append('type=1,fakename=fakevalue -usb')
    mount_command.append('')
    mount_command.append('-vnc')
    mount_command.append('fakelisten:fakedisplay')
    mount_command.append('-k')
    mount_command.append('"%skeymaps\%s"' % (INSTANCE_TEST_PATH, 'fakekeymap'))
    mount_command.append('-vga')
    mount_command.append('cirrus')
    mount_command.append('-device')
    mount_command.append('virtio-balloon-pci,id=balloon0,bus=pci.0,addr=0x5')
    mount_command.append('-rtc')
    mount_command.append('base=utc,driftfix=slew')
    mount_command.append('-no-shutdown')
    mount_command.append('')
    mount_command.append('-qmp')
    mount_command.append('tcp:127.0.0.1:fakeephemeralport,server,nowait')
    mount_commandstring =  ' '.join(mount_command)
    expected_command_tupple = (mount_commandstring, 'fakeport', 'fakeephemeralport')
    command_tupple = qemuwindriver._create_qemu_machine(instance, metadata_port, metadata_pid)
    self.assertEqual(expected_command_tupple, command_tupple)


  @mock.patch('driver.CONF')
  @mock.patch('driver.QemuWinDriver.__init__', mock.Mock(return_value = None))
  @mock.patch('driver.QemuWinDriver._get_instance_path', mock.Mock(return_value = INSTANCE_TEST_PATH))
  @mock.patch('driver.QemuWinDriver._get_ephemeral_port', mock.Mock(return_value = 'fakeport'))
  @mock.patch('driver.os.path')
  @mock.patch('driver.os.path.join', mock.Mock(side_effect= ['%s%s' % (INSTANCE_TEST_PATH, 'python.exe'),
  '%s%s' % (INSTANCE_TEST_PATH, 'metadataproxy.pid' )]))
  @mock.patch('driver.open', mock.mock_open(read_data = 'fakepid'), create = True)
  @mock.patch('driver.QemuWinDriver._create_subproccess', mock.Mock(return_value = 'fakeprocces'))
  def test_start_metadata_proxy(self, mock_conf, mock_path):
    instance = {'uuid':'fakeuuid'}
    tenant_id = 'faketenantid'
    qemuwindriver = QemuWinDriver()
    mock_path.dirname = INSTANCE_TEST_PATH
    mock_conf.nova_metadata_host = 'fakemetadatahost'
    mock_conf.nova_metadata_port = 'fakemetadataport'
    mock_conf.nova_metadata_shared_secret = 'fakemetadatasharedsecret'
    expected_return = 'fakeport' , 'fakepid'
    method_return = qemuwindriver._start_metadata_proxy(instance, tenant_id)
    self.assertEqual(expected_return, method_return)

  @mock.patch('driver.CONF')
  @mock.patch('driver.QemuWinDriver.__init__', mock.Mock(return_value = None))
  @mock.patch('driver.QemuWinDriver._get_instance_path', mock.Mock(return_value = INSTANCE_TEST_PATH))
  @mock.patch('driver.QemuWinDriver._get_ephemeral_port', mock.Mock(return_value = 'fakeport'))
  @mock.patch('driver.os.path')
  @mock.patch('driver.os.path.join', mock.Mock(side_effect= ['%s%s' % (INSTANCE_TEST_PATH, 'python.exe'),
  '%s%s' % (INSTANCE_TEST_PATH, 'metadataproxy.pid' )]))
  @mock.patch('driver.open', mock.mock_open(read_data = ''), create = True)
  @mock.patch('driver.QemuWinDriver._create_subproccess', mock.Mock(return_value = 'fakeprocces'))
  def test_start_metadata_proxy_no_pid_information(self, mock_conf, mock_path):
    instance = {'uuid':'fakeuuid'}
    tenant_id = 'faketenantid'
    qemuwindriver = QemuWinDriver()
    mock_path.dirname = INSTANCE_TEST_PATH
    mock_conf.nova_metadata_host = 'fakemetadatahost'
    mock_conf.nova_metadata_port = 'fakemetadataport'
    mock_conf.nova_metadata_shared_secret = 'fakemetadatasharedsecret'
    expected_return = 'fakeport' , ''
    method_return = qemuwindriver._start_metadata_proxy(instance, tenant_id)


if __name__ == "__main__":
  unittest.main()