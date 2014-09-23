
def set_nodes(nodes):
def restore_nodes():
class QemuWinDriver(driver.ComputeDriver):
    __init__:
    init_host: => Not Implemented
    list_instances: => Test with multiple instances, Test after removing instances, Test with no instances
    plug_vifs:=> Not Implemented
    unplug_vifs:=> Not Implemented
    disk_cachemode:=>Test if it calls “_supports_direct_io(CONF.instances_path)”
    _supports_direct_io:=>Test with empty dirpath, Test with confusing dirpaths(aka: paths that can also be interpreted as commands. Test different system responses
    getEl:=>Test if it calls “dom.getElementsByTagName”, Test a empty list at return
    getEls:=>Test if it calls “dom.getElementsByTagName”
    getText:=>Test if it calls “dom.getElementsByTagName”, Test a empty list at return
    qemuCommandNew:=>Check the return for both  CONF.qemu_home == None and CONF.qemu_home != None
    qemuCommandAddArg:=>Check if the appends are called
    qemuCommandStr:=>Test for Empty string
    _create_qemu_machine:=>Are we sure we have permission to write on the instances directory? If not, test that. Does entry.ChildNodes is guaranteed to always have at least one member? If not test when it is empty
    _start_metadata_proxy:=> Can we be sure that  the correct version of Python will be avaliable to the driver with a simple “python” command| the user has set the python_path on configuration? If not, test it
     -Add a comment about the nova_metadata_shared_secret on the installation page
    _create_instance_metadata_file:=>Test writing permission on the instances dir, Test with a non-existing dir.
    _check_machine_started:  
    start_qemu_instance:
    _next_vnc_display:
    spawn:=> Test if create image is being called, test if to_xml is being called, check the contents of socket_locks after the opperation, check if start_qemu_instance is called, see if _wait_for_qmp is called
    _wait_for_qmp:=> mock different numbers of tries until the return of a power_state.RUNNING result
    _get_console_log_path:=> check if libvirt_utils.get_instance_path is called with the correct parameter, test the return
     _get_disk_config_path:=>  check if libvirt_utils.get_instance_path is called with the correct parameter, test the return
     _chown_console_log_for_instance:=> Test with no permission to the instance dir
     _chown_disk_config_for_instance:=> Test with no permission to the instance dir
    _create_local:=> Test with and without a fs_format. See if the correct methods are called
    _create_ephemeral:=> See if create_local and disk.mkfs are called with the correct parameters Max_size parameter seems dead 
    _get_host_state:=> Test no permission to the instance path, check return vallues (maybe mock json return)
    _create_host_state_file:=> Test no permission on the instance path
    _get_host_arch: see if platform.architecture is correctly called, check return for both architectures
    _create_host_uuid: Test return value
    get_host_capabilities(self): Test how it handles exceptions from it’s called methods
    There’s a TODO there, is it still relevant? Do We want to set the host CPU as always appearing as a Intel? There is some way to find out the host-model on windows? Or does this information is irrelevant?
    get_host_uuid: Test if get_host_capabilities is called
    get_host_cpu_for_guest: Check how it handles exception from it’s called methods Is any of the information faked on the drive relevant? (CPU vendor, host-model and guestcpu.match)
    get_guest_cpu_config:=> Test for all valid and some invalid modes and models
    get_hypervisor_type:=> Check return type.
    get_hypervisor_version:=> Check return type
    set_cache_mode: =>check if the correct value of the variable is set
    get_guest_disk_config: => Check if  libvirt_info is called with the correct parameters
    get_guest_storage_config: =>Check if get_guest_disk_configuration is called with the correct parameters, check the return content
    get_guest_config_sysinfo:=>Check the return content
    get_guest_pci_device:=> Check if the parse_address is called with the correct parameters, check the contents of the return for a “real” usage
    get_guest_config:=> Check if instance_type_get is getting called with the correct parameters, check if inst_path is correct, check no permission to access the instance directory, Check return content.
    Can’t this method be refactored? It’s 175 lines long.
    get_guest_pci_device:=> Check return content
    to_xml:=> Check no permission on the instances directory, check file content against the return
    _create_image:=> Test for writing permission on image directory, 
    basepath:=> 
    image:=> test if image_backend.image is correctly called
    raw:=> check content of return
    live_snapshot:=>Check both a existing and an inexisting instance, check task state after the function has been called.
    snapshot:=> Check both a existing and an inexisting instance, check task state after the function has been called.
    Is there any difference between this function and the one above? They have the same parameter and code
    _get_ephemeral_port: => Check if _get_available_port is correctly called
    _get_available_port:=>   Simulate no avaliable ports on that range
    _get_qmp_connection:=> test for presence or ausence of sockets in the list, test for a busy qmp port
    _read_qmp_output:=> Check the different types the return message can be (including or not ‘event’ and ‘return’)
    _recv_qmp_output:=> test data bigger and smaller than 8192 bytes, and no data.    
    _negotiate_qmp_caps:=> test for no connection and busy socket
    _run_qmp_command:=> test losing the connection during a transaction
    _get_qmp_instance_status(self, instance):=> Check the diferent combination of Expected and current statuses
    reboot: => see if it calls _run_qmp_command with the correct parameters
    get_host_ip_addr:=> check response if this attribute is not present on conf
    set_admin_password: Pass
    inject_file: Pass
    resume_state_on_host_boot: Pass
    rescue: Pass
    unrescue: Pass
    poll_rebooting_instances: Pass
    migrate_disk_and_power_off: Pass
    finish_revert_migration: Pass
    post_live_migration_at_destination: Pass
    power_off:=> Test for sucessful and unsucessful power off
    power_on:=> check if popen is being correctly called, check the content of the metata variable
    soft_delete: Pass
    restore: Pass
    pause:=> Check if run_qmp_command uses the correct parameters
    unpause:=> Check if run_qmp_command uses the correct parameters
    suspend:=> Check if run_qmp_command uses the correct parameters
    resume:=> Check if run_qmp_command uses the correct parameters
    _get_instance_metadata:=> Check no access to instances dir, nonexisting metadata file
    destroy:=> check if the _kill method is called the correct number of times and with the correct parameters, check no permission on instance dir
    _kill:=> check the parameters of the subproccess call
    _execute_iscsi_command:=> check the parameters of the subproccess call, find ways in which popen may fail.
    _list_targets:=> check different return for the iscsi command call, and check against the final value of target_list
    _add_target_portal:=> Check if _execute_iscsi_command is being called with the correct parameters
    Why there’s an attribution on this method? Is some python iscsi exclusive thing?
    _login_target:=>Check if _execute_iscsi_command is being called with the correct parameters
    Why there’s an attribution on this method? Is some python iscsi exclusive thing?
    _logout_targe:=>Check if _execute_iscsi_command is being called with the correct parameters
    Why there’s an attribution on this method? Is some python iscsi exclusive thing?
    _connected_targets:=> Empty return on _execute_iscsi_command, test various combinations of connected targets
    _get_physical_drive:=> Empty return on _execute_iscsi_command, check valid and invalid target names and device types
    _get_iscsi_session_id:=> Check if _execute_iscsi_command is being called with the correct parameters, check empty return on _execute_iscsi_command
    _get_initiator_name:=> Check if _execute_iscsi_command is being called with the correct parameters, test both possible returns
    _run_qmp_human_monitor_command:=> Check if _run_qmp_command is being called with the correct parameters 
    _attach_volume:=> Test connection_info defective, test different responses for
get_physical_drive, test what happens once _get_instance_metadata fails, test what are the parameters which whom  _run_qmp_human_monitor_command is being called, test for both a valid and a invalid result in _check_qmp_result, check for failures in _create_instance_metadata_file
    _check_qmp_result:=> 
    attach_volume:=>Why is this necessary?
    detach_volume:=> Empty Metadata, metadata not containing “iscsi_devices”, no members on “iscsi_devices”, connection_info lacking information, check if, with correct information run qmp command is called, and if with incorrrect information it is not called
    swap_volume:=> test for sucessful and failed calls of atach and detach
    attach_interface:=>Pass
    detach_interface:=>Pass
    _get_power_state:=> Test for a empty return on _get_qmp_instance_status, test for each possible return and for a faked non-existing return
    _instance_exists:=> test for and empty list_of_instances
    get_info:=> test for a not existing instance, test failure at get_instance_metadata, test for empty metadata, test for empty result_cpus
    _get_value:=> test for an empty entry
    get_diagnostics:=> Test for non-existing instances, test for empty result on qmp command call, test return for a mocked response on run qmp human monitor command	
    get_all_bw_counters:=> The information here is so faked i’m not sure why we bothered with it
    interface_stats: Same as above
    _get_xml_desc:=> Test for unexisting file, test for no permission on dir
    get_console_output: =>Test for and non-existing file-path, test for no permission on the dir, check content of return
    get_vnc_console: => test for empty metadata, no vnc_proxyclient_address on configuration
    get_spice_console:=> Returns faked information
    get_console_pool_info:=> Returns faked information
    refresh_security_group_rules: => Returns faked information
    refresh_security_group_members:=> Returns faked information
    refresh_instance_security_rules:=> Returns faked information
    refresh_provider_fw_rules:=>Pass
    _get_host_disk_space:=> Test if GetDiskFreeSpaceExw is called with the correct arguments
    _get_host_disk_total:=> see if the return of _get_host_disk_space can be nulled, and if it is, test that
    _get_host_disk_free:=> see if the return of _get_host_disk_space can be nulled, and if it is, test that
    _get_host_disk_used:=> see if the return of _get_host_disk_space can be nulled, and if it is, test that
    _get_host_ram:=> Test if GlobalMemoryStatus is called with the correct arguments
    _get_host_free_ram: Rename the variable used on the for, => check if Win32_OperatingSystem is called
    _get_host_total_ram: Rename the variable used on the for, => check if Win32_OperatingSystem is called
    _get_host_used_ram: See if it can return a negative number
    get_available_resource: test return for some mocked information
    ensure_filtering_rules_for_instance:=> Returns None
    get_instance_disk_info:=> Returns None
    live_migration:=> Returns None, check if post_method is called with the correct parameters
    check_can_live_migrate_destination_cleanup:=> Returns None
    check_can_live_migrate_destination:=> Returns faked information
    check_can_live_migrate_source:=> Returns None
    finish_migration:=> Returns None
    confirm_migration:=> Returns None
    pre_live_migration:=> Returns None
    unfilter_instance:=> Returns None
    get_host_stats:=> Test for no Nodes, test for some nodes, test for empty host status Correct the error message (no node => no nodes)
    host_power_action:=> Does Nothing
    host_maintenance_mode:=> Test for mode==None and a mocked mode
    set_host_enabled:=> Test for enable==True and enable==False
    get_disk_available_least:=>Test for no instances, test for no permission on the instances dir, test returned information
    add_to_aggregate:=> Pass
    remove_from_aggregate:=> Pass
    get_volume_connector:=> Test for no information on ip or host on CONF, test for empty initiator name, test return content
    get_available_nodes:=> Check returned info 
    instance_on_disk:=> Test for permission on the instance dir
    list_instance_uuids:=> Check content of return
    


