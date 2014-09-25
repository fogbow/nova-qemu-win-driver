from driver import QemuWinDriver
import mock
import unittest
import random
import os
import time
import shutil

INSTANCE_TEST_PATH = 'C:\unittest'
instance_tracker = [];
class QemuWinDriverTestCase(unittest.TestCase):





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
 #   mock_supp.return_value = True
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

if __name__ == "__main__":
  unittest.main()