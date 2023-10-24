#!/usr/bin/python3

from datetime import date, datetime
from threading import Thread
from time import sleep
import subprocess, os, sys


global __title__, __author__, __email__, __version__, __last_updated__, __license__

__email__        =  'zhossain@protonmail.com'
__title__        =  'cis_audit.py'
__author__       =  'Zubair Hossain'
__last_updated__ =  '10/23/2023'
__version__      =  '1.0'
__license__      =  'GPLv3'


"""
                Notes:

    -   Throughout the code base you have '#TODO' flags if you search for it you can easily figure out
           what else needs to be upgraded / potential flaws that could be fixed

    -    SSH config fails remediation information has been disabled, at this time it is not recommended to run 
         SSH service as it has a big history of vulnerabilities.

         * If you would like to turn it back on, uncomment lines 8909-8910 (@CIS Report generation section)

    New features:

      [x] Upgrade help text with colors

      [x] Progress bar which increments a counter everytime a test is completed
      [x] Change the color of remediation cmds from cyan to orange

      [x] Auto detection of network_config file from known path (/etc/cis_audit/network_config.txt)
      [x] Upgrade progress bar theme to black & orange

      [x] Create users without a home dir & passwd

"""

global pkgmgr_installed, pkgmgr_rpm, pkgmgr_dpkg

pkgmgr_installed = False
pkgmgr_rpm       = False
pkgmgr_dpkg      = False


#===========================================================================
#                             CIS Core Functions                           #
#===========================================================================

def parse_args():

    l = len(sys.argv)

    invalid_arg = False

    if (l == 2):

        arg_1 = sys.argv[1].lower()

        if (arg_1 == '-h'):

            print('  ' + text_error("Option not found. Did u mean" + \
                         color_b('orange') + " --help " + \
                         color_reset() + "? ;]"))

            sys.exit(0)

        elif (arg_1 == '--help' or arg_1 == 'help'):

            print_header()
            print_help()
            sys.exit(0)

        elif (arg_1 == '-a' or arg_1 == '--audit' or arg_1 == 'audit'):

            if (check_if_user_root() == False):
                print(text_error('Root priviledge is required. Use sudo & try again'))
                sys.exit(1)

            path_to_config = '/etc/cis_audit/network_config.txt'

            if (os.path.isfile(path_to_config)):
                print_header()
                audit_live(path_to_config)

            else:

                print(text_error('Unable to locate \'network_config.txt\' file in \'%s\'' % path_to_config))
                sys.exit(1)

        else:
            invalid_arg = True

    elif (l == 3):

        arg_1 = sys.argv[1].lower()

        if (arg_1 == '-a' or arg_1 == '--audit' or arg_1 == 'audit'):

            if (check_if_user_root() == False):
                print(text_error('Root priviledge is required. Use sudo & try again'))
                sys.exit(1)

            if (os.path.isfile(sys.argv[2])):
                print_header()
                audit_live(sys.argv[2])
            else:
                print(text_error("The network config file '%s' is not valid" % sys.argv[2]))
                sys.exit(1)

        else:
            invalid_arg = True
    else:
        invalid_arg = True

    if (invalid_arg):
        print(text_error('Invalid option, try running --help'))
        sys.exit(1)


def audit_live(sysctl_config_file=''):

    pass_l = []
    fail_l = []

    remediation_msg_l = []

    sysctl_configs_validator = []
    sysctl_configs_user = []
    flags_inactive = []

    skip_sysctl_utility_checks = False

    sys_utils = ['mount', 'grep', 'systemctl', 'df', 'awk', 'xargs', 'find', \
            'journalctl', 'lsmod', 'uname', 'useradd', 'chage']

    paths = ['/usr/bin/', '/usr/sbin/', '/bin/', '/sbin/']
    output = check_if_files_are_valid(sys_utils, paths) 

    if (len(output[1]) != 0):
        print('\n' + text_error('The following tools need to be installed: '))

        for tool in output[1]:
            print('\n\t' + text_color_yellow("%s") % tool )

        print()
        sys.exit(0)

    # output = check_if_files_are_valid([sysctl_config_file], paths) 

    # def progress_bar_complete(index=1,index_range=10, \
    #         left_indent=15, right_indent=5):

    count_init = 0
    count_total = 201

    progress_bar_obj = ProgressBar(count_init, count_total)

    cursor_hide()

    # while (count_init < count_total):
    #     progress_bar_obj.print()
    #     count_init += 3
    #     progress_bar_obj.increment_count(3)
    #     sleep(1)

    print_block(4)

    progress_bar_obj.print()

    # sys.exit()

    sysctl_configs_user = get_sysctl_configs_system()
    sysctl_configs_validator = get_sysctl_config_validator(sysctl_config_file)

    if (len(sysctl_configs_validator) == 0):
        skip_sysctl_utility_checks = True

    validate_pkg_mgrs()

    ########################################################################
    #                    (1.1.1.1-8) Filesystem Check                      #
    ########################################################################

    fs_l = ['cramfs', 'jffs2', 'udf', 'hfs', 'hfsplus', 'freevxfs', 'squashfs', 'f2fs']

    for fs in fs_l:

        output = check_if_support_for_module_enabled(fs)

        if (output[0]):
            msg = '(1.1.1.1-8) Module %s is present, needs to be disabled in kernel (cut attack surface)' % (fs)
            fail_l.append(msg)
        else:
            msg = '(1.1.1.1-8) Module %s is not present (cut attack surface)' % (fs)
            pass_l.append(msg)


    """
    ## For testing purposes only

    ###########################################################################
    #                            CIS Report Generation                        #
    ###########################################################################

    fn = 'cis_report_%s.txt' % (datetime.today().strftime("%m-%d-%Y-%H-%M"))

    print_stats(pass_l, fail_l, True, fn)

    if (len(flags_inactive) != 0):
        print_sysctl_remediation(flags_inactive)

    if (len(remediation_msg_l) != 0):

        for line in remediation_msg_l:
            print(line)

    sys.exit()

    # """

    ########################################################################
    #                       (1.1.2-5) Tmp Dir Check                        #
    ########################################################################

    # We make a total of 4 checks here
    # 1) Checking if /tmp dir uses tmpfs
    # 2) nodev flag is set
    # 3) nosuid flag is set
    # 4) noexec flag is set

    test_failed_all = False

    msg = '(1.1.2) Found /tmp configured with tmpfs'

    cmd = "mount | grep -E '\s/tmp\s'"

    stdout, stderr, rc = run_cmd(cmd) 

    if (rc == 0):

        pass_l.append(msg)

        cmd = "mount | grep -E '\s/tmp\s' | cut -d' ' -f6"

        stdout, stderr, rc = run_cmd(cmd) 

        if (rc == 0):

            l = stdout.splitlines()
            _l = []

            for item in l:
                _item = item.strip().replace('(','').replace(')','').split(',')
                _l.append(_item)

            perm_opts = ['noexec', 'nosuid', 'nodev']

            for item in _l:

                output = check_if_all_element_in_list(item, perm_opts)

                if (output[0]):

                    msg = "(1.1.3) Found tmpfs in /tmp with 'nodev' set" 
                    pass_l.append(msg)

                    msg = "(1.1.4) Found tmpfs in /tmp with 'nosuid' set" 
                    pass_l.append(msg)

                    msg = "(1.1.5) Found tmpfs in /tmp with 'noexec' set" 
                    pass_l.append(msg)



                else:

                    #TODO: Separate the checks so that it is more specific

                    diff = [x for x in perm_opts if x not in output[1]]

                    for x in diff:
                        msg = "(1.1.3-5) Found tmpfs in /tmp with '%s' set" % (x)
                        pass_l.append(msg)

                    for x in output[1]:
                        msg = "(1.1.3-5) tmpfs in /tmp needs to have '%s' set" % (x)
                        fail_l.append(msg)
        else:
            test_failed_all = True

    else:
        test_failed_all = True

    if (test_failed_all):

        msg = '(1.1.2) /tmp needs to be configured with tmpfs'
        fail_l.append(msg)

        msg = "(1.1.3) tmpfs in /tmp needs to have 'noexec' set"
        fail_l.append(msg)

        msg = "(1.1.4) tmpfs in /tmp needs to have 'nosuid' set"
        fail_l.append(msg)

        msg = "(1.1.5) tmpfs in /tmp needs to have 'nodev' set"
        fail_l.append(msg)


    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################
    #       (1.1.6) Checking whether /var is on a separate partition       #
    #               * Used by system services / daemons                    #
    ########################################################################

    cmd = "mount | grep -E '\s/var\s'"

    stdout, stderr, rc = run_cmd(cmd) 

    if (rc == 0):
        msg = '(1.1.6) Found /var to be using a separate partition'
        pass_l.append(msg)
    else:
        msg = '(1.1.6) /var needs to be on a separate partition'
        fail_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################
    #  (1.1.7-1.1.10) Checking whether /var/tmp is on a separate partition #
    #             * Used by users / user apps for temp storage             #
    ########################################################################

    # We make a total of 4 checks here
    # 1) Checking if /var/tmp dir uses separate partition
    # 2) nodev flag is set
    # 3) noexec flag is set
    # 4) nosuid flag is set

    test_failed_all = False

    msg = '(1.1.7) Found /var/tmp configured on a separate partition'

    cmd = "mount | grep -E '\s/var/tmp\s'"

    stdout, stderr, rc = run_cmd(cmd) 

    if (rc == 0):

        pass_l.append(msg)

        cmd = "mount | grep -E '\s/var/tmp\s' | cut -d' ' -f6"

        stdout, stderr, rc = run_cmd(cmd) 

        if (rc == 0):

            l = stdout.splitlines()
            _l = []

            for item in l:
                _item = item.strip().replace('(','').replace(')','').split(',')
                _l.append(_item)

            perm_opts = ['noexec', 'nosuid', 'nodev']

            for item in _l:

                output = check_if_all_element_in_list(item, perm_opts)

                if (output[0]):

                    msg = "(1.1.8) Found /var/tmp with 'nodev' set" 
                    pass_l.append(msg)

                    msg = "(1.1.9) Found /var/tmp with 'noexec' set" 
                    pass_l.append(msg)

                    msg = "(1.1.10) Found /var/tmp with 'nosuid' set" 
                    pass_l.append(msg)


                else:

                    #TODO: Separate the checks so that it is more specific

                    diff = [x for x in perm_opts if x not in output[1]]

                    for x in diff:
                        msg = "(1.1.8-10) Found /var/tmp with '%s' set" % (x)
                        pass_l.append(msg)

                    for x in output[1]:
                        msg = "(1.1.8-10) /var/tmp needs to have '%s' set" % (x)
                        fail_l.append(msg)
        else:
            test_failed_all = True
    else:
        test_failed_all = True

    if (test_failed_all):

        msg = '(1.1.7) /var/tmp needs to be configured with tmpfs'
        fail_l.append(msg)

        msg = "(1.1.8) /var/tmp needs to have 'nodev' set"
        fail_l.append(msg)

        msg = "(1.1.9) /var/tmp needs to have 'noexec' set"
        fail_l.append(msg)

        msg = "(1.1.10) /var/tmp needs to have 'nosuid' set"
        fail_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################
    #     (1.1.11) Checking whether /var/log is on a separate partition    #
    #            * Used by system services to store log data               #
    ########################################################################

    cmd = "mount | grep /var/log"

    stdout, stderr, rc = run_cmd(cmd) 

    if (rc == 0):
        msg = '(1.1.11) Found /var/log using a separate partition'
        pass_l.append(msg)
    else:
        msg = '(1.1.11) /var/log needs to be on a separate partition'
        fail_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################
    # (1.1.12) Checking whether /var/log/audit is on a separate partition  #
    #            * Used by system services to store log data               #
    ########################################################################

    cmd = "mount | grep /var/log/audit"

    stdout, stderr, rc = run_cmd(cmd) 

    if (rc == 0):
        msg = '(1.1.12) Found /var/log/audit using a separate partition'
        pass_l.append(msg)
    else:
        msg = '(1.1.12) /var/log/audit needs to be on a separate partition'
        fail_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################
    #     (1.1.13-14) Checking whether /home is on a separate partition    #
    #           * Otherwise can lead to resource exhaustion attacks        #
    ########################################################################

    # We make a total of 2 checks here                
    # 1) Checking if /home dir uses separate partition
    # 2) nodev flag is set                            

    test_failed_all = False

    #TODO: The commands are not validating if /home is on a separate partition
    cmd = "mount | grep /home"

    stdout, stderr, rc = run_cmd(cmd) 

    if (rc == 0):

        msg = '(1.1.13) Found /home using a separate partition'
        pass_l.append(msg)

        cmd = "mount | grep -E '\s/home\s' | cut -d' ' -f6"

        stdout, stderr, rc = run_cmd(cmd) 

        if (rc == 0):

            l = stdout.splitlines()
            _l = []

            for item in l:
                _item = item.strip().replace('(','').replace(')','').split(',')
                _l.append(_item)

            perm_opts = ['nodev']

            for item in _l:

                output = check_if_all_element_in_list(item, perm_opts)

                if (output[0]):

                    msg = "(1.1.14) Found /home with 'nodev' set" 
                    pass_l.append(msg)

                else:

                    msg = "(1.1.14) /home needs to have 'nodev' set" 
                    fail_l.append(msg)
        else:
            msg = "(1.1.14) /home needs to have 'nodev' set" 
            fail_l.append(msg)
    else:
        test_failed_all = True

    if (test_failed_all):
        msg = "(1.1.13) /home needs to be on a separate partition"
        fail_l.append(msg)
        msg = "(1.1.14) /home needs to have 'nodev' set"
        fail_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################
    #       (1.1.15-17) Checking whether /dev/shm has 'nodev' option set   #
    #     * Otherwise it may allow users to have their own block devices   #
    ########################################################################

    # We make a total of 3 checks here      
    # 1) nodev flag is set                  
    # 2) nosuid flag is set                 
    # 3) noexec flag is set                 

    test_failed_all = False

    cmd = "mount | grep -E '\s/dev/shm\s'"

    stdout, stderr, rc = run_cmd(cmd) 

    if (rc == 0):

        cmd = "mount | grep -E '\s/dev/shm\s' | cut -d' ' -f6"

        stdout, stderr, rc = run_cmd(cmd) 

        if (rc == 0):

            l = stdout.splitlines()
            _l = []

            for item in l:
                _item = item.strip().replace('(','').replace(')','').split(',')
                _l.append(_item)

            perm_opts = ['noexec', 'nosuid', 'nodev']

            for item in _l:

                output = check_if_all_element_in_list(item, perm_opts)

                if (output[0]):

                    msg = "(1.1.15) Found /dev/shm with 'noexec' set" 
                    pass_l.append(msg)

                    msg = "(1.1.16) Found /dev/shm with 'nosuid' set" 
                    pass_l.append(msg)

                    msg = "(1.1.17) Found /dev/shm with 'nodev' set" 
                    pass_l.append(msg)

                else:

                    diff = [x for x in perm_opts if x not in output[1]]

                    #TODO make this control numbers more specific than grouping
                    #     them up together like this

                    for x in diff:
                        msg = "(1.1.15-17) Found /dev/shm with '%s' set" % (x)
                        pass_l.append(msg)

                    for x in output[1]:
                        msg = "(1.1.15-17) /dev/shm needs to have '%s' set" % (x)
                        fail_l.append(msg)
        else:
            test_failed_all = True
    else:
        test_failed_all = True

    if (test_failed_all):

        msg = "(1.1.15-17) /dev/shm needs to be on a separate partition"
        fail_l.append(msg)

        msg = "(1.1.15) dev/shm needs to have 'nodev' set"
        fail_l.append(msg)

        msg = "(1.1.16) /dev/shm needs to have 'nosuid' set"
        fail_l.append(msg)

        msg = "(1.1.17) /dev/shm needs to have 'noexec' set"
        fail_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################
    #     (1.1.21) Ensure sticky bit is set on all world writable dirs     #
    #         * Otherwise users are able to create / remove dirs           #
    ########################################################################

    cmd = "df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null"

    stdout, stderr, rc = run_cmd(cmd)

    if (stdout.strip() == ''):
        msg = '(1.1.21) Found sticky bit set on all world writable directories'
        pass_l.append(msg)
    else:
        msg = '(1.1.21) Sticky bit is not set on some of the world writable directories'
        fail_l.append(msg)

        msg = color_symbol_debug() + text_color_yellow(' Sticky bit needs to be set on the following dirs:\n\n')

        output = stdout.splitlines()

        fl = []

        for f in output:

            if (f.startswith('/home')):
                pass
            else:
                fl.append(f)

        for fp in fl:
            msg += text_color_orange('\t  sudo chmod +t %s\n' % fp.strip())

        remediation_msg_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################
    #      (1.1.22) Checking whether automatic mounting of disks           #
    #           or removable drive is enabled (autofs)                     #
    #    * Allows user to have access even if no permission allowed        #
    ########################################################################

    cmd = "systemctl is-enabled autofs"

    stdout, stderr, rc = run_cmd(cmd) 

    if (rc == 0):
        msg = '(1.1.22) Automatic mounting of drive is enabled (autofs)'
        fail_l.append(msg)
    else:
        msg = '(1.1.22) Automatic mounting of drives is disabled (autofs)'
        pass_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################
    #            (1.1.23) Disabling USB Storage (usb-storage)              #
    ########################################################################

    cmd = "lsmod | grep usb-storage"

    stdout, stderr, rc = run_cmd(cmd) 

    if (rc == 0 and len(stdout.splitlines()) == 0):
        msg = '(1.1.23) usb storage is disabled'
        pass_l.append(msg)
    else:
        msg = "(1.1.23) usb storage module needs to be disabled"
        fail_l.append(msg)
        msg = color_symbol_debug() + text_color_yellow(' Remove modules used for usb storage: ')
        msg += "\n\n\t  " + text_color_orange("sudo rmmod usb-storage" + "\n")
        remediation_msg_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################
    #  (1.3.1) Check whether AIDE filesystem monitoring tool is installed  #
    ########################################################################

    output = search_for_file('/usr/bin', 'aide')

    if (output[0]):
        msg = '(1.3.1) Aide filesystem monitoring tool is installed'
        pass_l.append(msg)
    else:
        msg = '(1.3.1) Aide filesystem monitoring tool needs to be installed'
        fail_l.append(msg)
        msg = color_symbol_debug() + text_color_yellow(' Install Aide filesystem monitoring tool: ')
        msg += "\n\n\t  " + text_color_orange(pkgmgr_print_install_cmd('aide')+ "\n")
        remediation_msg_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################
    #       (1.3.2) Validating whether Aide tool is enabled & active       #
    ########################################################################

    cmd1 = "systemctl is-enabled aidcheck.service"
    cmd2 = "systemctl is-enabled aidcheck.timer"

    stdout1, stderr1, rc1 = run_cmd(cmd1) 
    stdout2, stderr2, rc2 = run_cmd(cmd2) 

    if (rc1 == 0 and rc2 == 0):
        msg = '(1.3.2) Aide tool is enabled & active'
        pass_l.append(msg)
    else:
        msg = '(1.3.2) Aide tool needs to be configured, enabled & active'
        fail_l.append(msg)
        msg = color_symbol_debug() + text_color_yellow(' Configure Aide tool:\n\n')
        text = text_color_orange("\t  sudo cp ./config/aidecheck.service /etc/systemd/system/aidecheck.service\n")
        text += text_color_orange("\t  sudo cp ./config/aidecheck.timer /etc/systemd/system/aidecheck.timer\n")
        text += text_color_orange("\t  sudo chmod 0644 /etc/systemd/system/aidecheck.*\n")
        text += text_color_orange("\t  sudo systemctl reenable aidecheck.timer\n")
        text += text_color_orange("\t  sudo systemctl restart aidecheck.timer\n")
        text += text_color_orange("\t  sudo systemctl daemon-reload\n")
        msg += text
        remediation_msg_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################
    # (1.4.1) Validating whether boot config file is set to rw permission  #
    #                           for root only                              #
    ########################################################################

    dir_path1 = '/boot/grub'
    dir_path2 = '/boot/grub2'

    path = ''

    skip_check = False

    if (os.path.isdir(dir_path1)):
        path = dir_path1
    elif (os.path.isdir(dir_path2)):
        path = dir_path2
    else:
        skip_check = True

    if (not skip_check):

        fp = os.path.join(path, 'grub.cfg')

        error_msg = color_symbol_debug() + text_color_yellow(' Boot configuration file needs to be readable & writable by root only\n')
        cmd = "  sudo chown root:root %s\n" % fp 
        error_msg += "\n\t" + text_color_orange(cmd)
        cmd = "  sudo chmod og-rwx %s\n" % fp 
        error_msg += "\t" + text_color_orange(cmd)

        attrs = os.stat(fp)
        perm = oct(attrs.st_mode)
        user_perm = int(perm[-3])
        group_perm = int(perm[-2])
        other_perm = int(perm[-1])

        if (attrs.st_uid == 0 and attrs.st_gid == 0 and \
                user_perm >= 6 and group_perm == 0 and other_perm == 0):
            msg = '(1.4.1) Boot configuration file is readable & writable by root only'
            pass_l.append(msg)
        else:
            msg = '(1.4.1) Boot configuration file needs to be readable & writable by root only'
            fail_l.append(msg)
            remediation_msg_l.append(error_msg)
    else:
        print(text_error('Unable to find path to boot directory, skipping permission check for boot.cfg file'))

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################
    #              (1.4.2) Ensure bootloader password is set               #
    ########################################################################

    dir_path1 = '/boot/grub/'
    dir_path2 = '/boot/grub2/'

    ## We're assuming grub_version 2 is installed on system

    path = ''

    grub_pw_protected = False

    if (os.path.isdir(dir_path1)): # /boot/grub

        path = dir_path1

        fp1 = os.path.join(path, 'menu.lst')
        fp2 = os.path.join(path, 'grub.cfg')

        if (os.path.isfile(fp1)):

            cmd = 'grep "^\s*password" %s' % fp1

            stdout, stderr, rc = run_cmd(cmd) 

            if (rc == 0):

                txt = text_color_yellow(stdout.splitlines()[0])
                msg = "Found grub pw protected: '%s'" % txt
                pass_l.append(msg)
                grub_pw_protected = True

        elif (grub_pw_protected == False and os.path.isfile(fp2)):

            cmd1 = 'grep "^\s*set superusers" %s' % fp2
            cmd2 = 'grep "^\s*password" %s' % fp2

            stdout1, stderr1, rc1 = run_cmd(cmd1) 
            stdout2, stderr2, rc2 = run_cmd(cmd2) 

            if (rc1 == 0 and rc2 == 0):
                txt1 = text_color_yellow(stdout1.splitlines()[0])
                txt2 = text_color_yellow(stdout2.splitlines()[0])
                msg = "Found grub pw protected:\n\n"
                msg += '\t%s\n' % txt1
                msg += '\t%s\n' % txt2
                pass_l.append(msg)
                grub_pw_protected = True

    if (grub_pw_protected == False and os.path.isdir(dir_path2)): # /boot/grub2

        path = dir_path2
        fp1 = os.path.join(path, 'user.cfg')

        cmd = 'grep "^\s*GRUB2_PASSWORD" %s' % fp1

        stdout, stderr, rc = run_cmd(cmd) 

        if (rc == 0):

            txt = text_color_yellow(stdout.splitlines()[0])
            msg = "(1.4.2) Found grub pw protected: %s" % txt
            pass_l.append(msg)
            grub_pw_protected = True

    if (grub_pw_protected == False):

        msg = '(1.4.2) Bootloader (Grub) needs to be password protected'

        fail_l.append(msg)

        ## Remediation messages

        error_msg = ''

        error_msg = color_symbol_debug() + text_color_yellow(' Password protect Grub Bootloader\n')

        cmd = "  sudo grub-mkpasswd-pbkdf2\n"

        error_msg += "\n\t" + text_color_orange(cmd)

        error_msg += '\n' + text_color_yellow('          Edit \'/etc/grub.d/00_header\' & add the following information,' + \
                                                      ' also make sure to replace username & password fields:\n')
        cmd = """
              sudo cat <<EOF
              set superusers="<username>"
              password_pbkdf2 <username> <encrypted-password>
              EOF"""

        error_msg += "\t              " + text_color_green(cmd)

        error_msg += '\n\n' + text_color_yellow('          Update Grub config\n')

        cmd = "sudo grub-mkconfig -o /boot/grub/grub.cfg\n"

        error_msg += "\n              " + text_color_orange(cmd)

        remediation_msg_l.append(error_msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################
    #           (1.4.3) Ensure authentication required for root user       #
    #  * There's mention of single user mode in title, that is incorrect   #
    ########################################################################

    cmd = "grep '^root:[*\!]:' /etc/shadow"

    stdout, stderr, rc = run_cmd(cmd)

    if (rc == 0):
        msg = "(1.4.3) No password set for root account"
        fail_l.append(msg)
        txt = color_symbol_info() + text_color_yellow(' Set a password for root account: \n\n') 
        txt += text_color_orange('\t  sudo passwd root') + '\n'
        remediation_msg_l.append(txt)
    else:
        msg = '(1.4.3) Root user account is password protected'
        pass_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################
    #              (1.5.1) Ensure core dumps are restricted                #
    ########################################################################
    # TODO: Passive version that parses sysctl.conf file                    
    # 1) Checking systemctl service to see if coredump tool is installed    
    #    * If coredump is installed we further check the following:         
    #       a) Checking if hard limit is set in config file                 
    #       b) Checking sysctl configs to make sure setuid programs don't   
    #          dump errors to core file                                     


    cmd1 = 'systemctl is-enabled coredump.service'
    cmd2 = 'systemctl is-enabled systemd-coredump.socket'

    stdout1, stderr1, rc1 = run_cmd(cmd1)
    stdout2, stderr2, rc2 = run_cmd(cmd2)

    msg = "Core dumps need to be restricted"

    txt = ''

    if (rc1 == 0 or rc2 == 0): # Found to be active so we make 2 more checks

        cmd1 = 'grep "hard core" /etc/security/limits.conf /etc/security/limits.d/*'

        cmd2 = 'sysctl fs.suid_dumpable'

        stdout1, stderr1, rc1 = run_cmd(cmd1)

        if (not skip_sysctl_utility_checks):
            stdout2, stderr2, rc2 = run_cmd(cmd2)

        failed_test = False

        if (rc1 == 0):

            failed_test = True

            txt = color_symbol_debug() + text_color_yellow(' Add the following lines to /etc/security/limits.conf: ') + '\n\n'
            txt += '\t    ' + text_color_green("'* hard core 0'") + '\n'

        if (not skip_sysctl_utility_checks and rc2 == 0):

            failed_test = True

            if (rc1 == 0):
                txt += '\n'

            txt += color_symbol_debug() + text_color_yellow(' Add the following lines to /etc/sysctl.conf: ') + '\n\n'
            txt += '\t  ' + text_color_green("fs.suid_dumpable = 0") + '\n\n'
            txt += color_symbol_debug() + text_color_yellow(' Disable core dumps by setuid programs:\n\n')
            txt += '\t  ' + text_color_orange("sudo sysctl -w fs.suid_dumpable=0") + '\n'

        if (failed_test):
            fail_l.append(msg)
            remediation_msg_l.append(txt)
        else:
            msg = '(1.5.1) Core dumps are restricted (hard limit set & core dumps by setuid programs are disabled)'
            pass_l.append(msg)

    else:
        msg = '(1.5.1) Core dumps are restricted (not installed on system)'
        pass_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ##################################################################################
    # (1.5.2) Validating whether No Execute (NX) or XD is enabled in kernel settings #
    ##################################################################################
    #TODO: Alternative search using dmesg in case run on older systems without        
    #      journalctl tool present                                                    

    cmd = "journalctl | grep 'protection: active'"
    
    stdout, stderr, rc = run_cmd(cmd) 

    if (rc == 0):
        msg = "(1.5.2) Found No Execute (NX) & XD protections enabled in kernel"
        pass_l.append(msg)
    else:
        msg = '(1.5.2) No Execute (NX) & XD protections need to configured in kernel'
        fail_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###################################################################################
    # (1.5.3) Validating whether ASLR (Address Space Layout Randomization) is enabled #
    ###################################################################################
    # TODO: Passive version requires parsing of sysctl.conf                            

    if (not skip_sysctl_utility_checks):

        cmd = "sysctl kernel.randomize_va_space"
        stdout, stderr, rc = run_cmd(cmd) 

        val = stdout.splitlines()[0].split('=')[1].strip()

        if (rc != 0 and val == '2'):
            msg = "(1.5.3) Found ASLR (Address Space Layout Randomization) protection active"
            pass_l.append(msg)
        else:
            msg = "(1.5.3) Need to configure ASLR (Address Space Layout Randomization) protection"
            fail_l.append(msg)
            txt = color_symbol_debug() + text_color_yellow(' Enable ASLR protection: ') + '\n\n'
            txt += '\t  ' + text_color_orange("sudo sysctl -w kernel.randomize_va_space=2") + '\n'
            remediation_msg_l.append(txt)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #   (1.5.4) Validating whether prelink is installed, if so disable it     #
    #           * Prelink modifies binaries which allows them to              #
    #             be resolved faster at runtime                               #
    ###########################################################################

    output = pkgmgr_search_if_installed('prelink')

    if (output) : # Prelink is installed

        msg = "(1.5.4) Prelink tool needs to be uninstalled" 
        fail_l.append(msg)
        msg = text_color_yellow("\tUninstall prelink tool: \n")
        msg += '\n\t    ' + text_color_orange(pkgmgr_print_install_cmd('prelink')) + '\n'
        remediation_msg_l.append(msg)


    else:
        msg = "(1.5.4) Prelink tool is not installed"
        pass_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #       (1.6.1.1) Validate whether SELinux or AppArmor are installed      #
    ###########################################################################

    output1 = pkgmgr_search_if_installed('libselinux')
    output2 = pkgmgr_search_if_installed('libselinux1')

    output3 = pkgmgr_search_if_installed('apparmor')

    if (output1 or output2 or output3):

        msg = "(1.6.1.1) Apparmor / SeLinux is installed"

        pass_l.append(msg)

    else:
        msg = "(1.6.1.1) Apparmor / SeLinux needs to be installed"
        fail_l.append(msg)
        msg = '\n\t  ' + text_color_orange(pkgmgr_print_install_cmd('libselinux1')) + '\n'
        remediation_msg_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    # (1.6.2.1) Validate whether SELinux is not disabled in boot loader config#
    ###########################################################################

    #TODO: Remediation

    path1 = '/boot/grub'
    path2 = '/boot/grub2'

    boot_dir = ''

    if (os.path.isdir(path1)):
        boot_dir = path1
    else:
        boot_dir = path2

    fp1 = os.path.join(boot_dir, 'menu.lst')
    fp2 = os.path.join(boot_dir, 'grub.cfg')

    cmd1 = 'grep "^\s*selinux=0*" %s' % fp1
    cmd2 = 'grep "^\s*enforcing=0*" %s' % fp1
    cmd3 = 'grep "^\s*selinux=0*" %s' % fp2
    cmd4 = 'grep "^\s*enforcing=0*" %s' % fp2

    stdout1, stderr1, rc1 = run_cmd(cmd1) 
    stdout2, stderr2, rc2 = run_cmd(cmd2) 
    stdout3, stderr3, rc3 = run_cmd(cmd3) 
    stdout4, stderr4, rc4 = run_cmd(cmd4) 

    if (rc1 == 0 or rc2 == 0 or rc3 == 0 or rc4 == 0):
        msg = "(1.6.2.1) Found selinux disabled in boot config" 
        fail_l.append(msg)
    else:
        msg = "(1.6.2.1) Selinux not disabled in boot config" 
        pass_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #              (1.6.2.2)  Ensure SELinux state is enforcing               #
    ###########################################################################

    cmd1 = 'grep SELINUX=enforcing /etc/selinux/config'
    cmd2 = 'sestatus | grep enabled'
    cmd3 = 'sestatus | grep enforcing'

    stdout1, stderr1, rc1 = run_cmd(cmd1) 
    stdout2, stderr2, rc2 = run_cmd(cmd2) 
    stdout3, stderr3, rc3 = run_cmd(cmd3) 

    if ((rc2 == 0 and rc3 == 0) or rc1 == 0):
        msg = '(1.6.2.2) SELinux state is active and enforcing'
        pass_l.append(msg)
    else:
        msg = '(1.6.2.2) SELinux state needs to be active and enforcing'
        fail_l.append(msg)

        msg = color_symbol_debug() + text_color_yellow(' Edit /etc/selinux/config file' + \
                '& update the following parameter:\n\n')
        msg += '\t  ' + text_color_green('SELINUX=enforcing\n')
        remediation_msg_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #              (1.6.2.4) Ensure SELinux policy is configured              #
    ###########################################################################

    cmd1 = 'grep SELINUXTYPE=targeted /etc/selinux/config'
    cmd2 = 'sestatus | grep -i policy | grep -i targeted'

    stdout1, stderr1, rc1 = run_cmd(cmd1) 
    stdout2, stderr2, rc2 = run_cmd(cmd2) 

    if (rc1 == 0 or rc2 == 0):
        msg = '(1.6.2.4) SELinux policy is configured'
        pass_l.append(msg)
    else:
        msg = '(1.6.2.4) SELinux policy needs to be configured'
        fail_l.append(msg)

        msg = color_symbol_debug() + text_color_yellow(' Edit /etc/selinux/config file &' + \
                ' update the following parameter::\n\n')
        msg += '\t  ' + text_color_green('SELINUXTYPE=targeted\n')
        remediation_msg_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #             (1.6.2.4) Ensure SETroubleshoot is not installed            #
    ###########################################################################

    output1 = pkgmgr_search_if_installed('setroubleshoot')

    if (output1):
        msg = '(1.6.2.4) Setroubleshoot service needs to be uninstalled as it can reveal unprotected files\n\n'
        fail_l.append(msg)

        msg = color_symbol_debug() + text_color_yellow(' Uninstall setroubleshoot tool:\n\n')
        msg += '\t  ' + text_color_orange(pkgmgr_print_uninstall_cmd('setroubleshoot')) + '\n'
        remediation_msg_l.append(msg)
    else:
        msg = '(1.6.2.4) setroubleshoot service is not installed'
        pass_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    # (1.6.2.5) Ensure the MCS Translation Service (mcstrans) is not installed#
    ###########################################################################

    output1 = pkgmgr_search_if_installed('mcstrans')

    if (output1):
        msg = '(1.6.2.5) Mcstrans service if installed, could lead to vulnerable code running on the system'
        fail_l.append(msg)

        msg = color_symbol_debug() + text_color_yellow(' Uninstall the MCS Translation tool:\n\n')
        msg += '\t  ' + text_color_orange(pkgmgr_print_uninstall_cmd('mcstrans')) + '\n'
        remediation_msg_l.append(msg)
    else:
        msg = '(1.6.2.5) mcstrans service is not installed'
        pass_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #               (1.6.2.6) Ensure no unconfined daemons exist              #
    ###########################################################################

    cmd1 = 'ps -eZ | grep -E "initrc" | grep -E -v -w "tr|ps|grep|bash|awk" | tr ":" " " | awk "{ print $NF }"'

    stdout1, stderr1, rc1 = run_cmd(cmd1) 

    nl = stdout1.strip().splitlines()

    if (rc1 == 0 and len(nl) == 0): 

        msg = '(1.6.2.6) No unconfined daemons were found' 
        pass_l.append(msg)

    else:

        msg = '(1.6.2.6) Unconfined daemons were found' 
        fail_l.append(msg)

        msg = color_symbol_debug() + text_color_yellow(' The following unconfined daemons need to be disabled\n\n')

        for line in nl:
            msg += text_color_orange('\t  %s\n' % line)

        remediation_msg_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    # (1.6.3.1) Ensure AppArmor is not disabled in bootloader configuration   #
    ###########################################################################

    dir_path1 = '/boot/grub/'
    dir_path2 = '/boot/grub2/'

    ## We're assuming grub_version 2 is installed on system

    path = ''
    
    skip_check = False

    if (os.path.isdir(dir_path1)): # /boot/grub 
        path = dir_path1
    elif (os.path.isdir(dir_path2)):
        path = dir_path2
    else:
        skip_check = True

    if (not skip_check):

        fp1 = os.path.join(path, 'menu.lst')
        fp2 = os.path.join(path, 'grub.cfg')

        if (os.path.isfile(fp1)):

            cmd = 'grep "^\s*apparmor=0*" %s' % fp1

            stdout, stderr, rc = run_cmd(cmd) 

            if (rc == 0):

                msg = "(1.6.3.1) AppArmor is disabled in boot config"
                fail_l.append(msg)

                txt1 = color_symbol_debug() + text_color_yellow(' Enable apparmor' + \
                                'by editing /etc/default/grub and removing all instances of apparmor=0')
                remediation_msg_l.append(txt1)

            else:
                msg = "(1.6.3.1) AppArmor is not disabled in boot config"
                pass_l.append(msg)
    else:

        pass

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #           (1.6.3.2) Ensure all AppArmor Profiles are enforcing          #
    ###########################################################################

    cmd1 = 'apparmor status | grep complain | grep profiles'
    cmd2 = 'apparmor_status | grep unconfined | grep processes'

    stdout1, stderr1, rc1 = run_cmd(cmd1)
    stdout2, stderr2, rc2 = run_cmd(cmd2)

    stdout = stdout1
    stderr = stderr1
    rc = rc1

    if (rc1 == 0 or rc2 == 0):

        msg = '(1.6.3.2) AppArmor profiles needs to be set to enforcing mode'
        fail_l.append(msg)

        msg = color_symbol_debug() + text_color_yellow(' Set AppArmor profiles to enforcing mode:\n\n')
        msg += text_color_orange('\t  enforce /etc/apparmor.d/*\n')
        remediation_msg_l.append(msg)

    else:

        msg = '(1.6.3.2) No AppArmor profiles were found in complain / confined mode'
        pass_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #    (1.7.1.1) Ensure motd (message of the day) is configured properly    #
    ###########################################################################

    cmd1 = "grep -E -i \"(\\v|\\r|\\m|\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/\"//g'))\" /etc/motd"

    stdout1, stderr1, rc1 = run_cmd(cmd1)

    nl = stdout1.strip().splitlines()

    if (rc1 == 0 and len(nl) == 0):

        msg = '(1.7.1.1) Motd (Message of the day) is configured properly'
        pass_l.append(msg)

    else:

        msg = '(1.7.1.1) Motd (Message of the day) needs to be configured'
        fail_l.append(msg)

        msg = color_symbol_debug() + text_color_yellow(' Edit /etc/motd so that OS name, version, etc. information are not present\n')
        remediation_msg_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #    (1.7.1.2) Ensure login local warning banner is configured properly   #
    ###########################################################################

    cmd1 = "grep -E -i \"(\\v|\\r|\\m|\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/\"//g'))\" /etc/issue"

    stdout1, stderr1, rc1 = run_cmd(cmd1) 

    nl = stdout1.strip().splitlines()

    if (rc1 == 0 and len(nl) == 0): 

        msg = '(1.7.1.2) Login local warning banner is configured properly' 
        pass_l.append(msg)

    else:

        msg = '(1.7.1.2) Login local warning banner needs to be configured properly' 
        fail_l.append(msg)

        msg = color_symbol_debug() + text_color_yellow(' Configure login local banner:\n\n')
        msg += text_color_orange('\t  echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue\n')
        remediation_msg_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    #TODO: 1.7.1.3

    ###########################################################################
    #        (1.7.1.4) Ensure permissions on /etc/motd are configured         #
    ###########################################################################
    # /etc/motd needs to be:                                                   
    # 1) Owned by root only                                                    
    # 2) Permissions need to be set to 644                                     

    test_failed = False

    if (os.path.isfile('/etc/motd')):

        attrs = os.stat('/etc/motd')

        uid = attrs.st_uid
        gid = attrs.st_gid

        msg_extra = ''

        if (uid != 0 or gid != 0):
            test_failed = True
            msg_extra = text_color_red("\tUID / GID should be limited to 0 / root user only\n\n")
            msg_extra += text_color_orange("\t  sudo chown root:root /etc/motd\n\n")

        perm = oct(attrs.st_mode)
        user_perm = int(perm[-3])
        group_perm = int(perm[-2])
        other_perm = int(perm[-1])

        if (not (user_perm == 6 and group_perm == 4 and other_perm == 4)):
            test_failed = True
            msg_extra += text_color_red("\tPermissions need to be set to 644\n\n")
            msg_extra += text_color_orange("\t  sudo chmod 644 /etc/motd\n")

        if (test_failed): 

            msg = "(1.7.1.4) Appropriate permissions for '/etc/motd' file need to be configured" 
            fail_l.append(msg)


            msg = color_symbol_debug() + text_color_yellow(" Configure security settings for '/etc/motd' file\n\n")
            msg += msg_extra
            remediation_msg_l.append(msg)

        else:

            msg = "(1.7.1.4) '/etc/motd' file is configured with correct permissions" 
            pass_l.append(msg)
    else:
        pass

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #        (1.7.1.5) Ensure permissions on /etc/issue are configured        #
    ###########################################################################
    # /etc/issue needs to be:                                                  
    # 1) Owned by root only                                                    
    # 2) Permissions need to be set to 644                                     

    test_failed = False

    if (os.path.isfile('/etc/issue')):

        attrs = os.stat('/etc/issue')

        uid = attrs.st_uid
        gid = attrs.st_gid

        msg_extra = ''

        if (uid != 0 or gid != 0):
            test_failed = True
            msg_extra += text_color_red("\tUID / GID should be limited to 0 / root user only\n\n")
            msg_extra += text_color_orange("\t    sudo chown root:root /etc/issue\n\n")

        perm = oct(attrs.st_mode)
        user_perm = int(perm[-3])
        group_perm = int(perm[-2])
        other_perm = int(perm[-1])

        if (not (user_perm == 6 and group_perm == 4 and other_perm == 4)):

            test_failed = True
            msg_extra += text_color_red("\tPermissions need to be set to 644\n\n")
            msg_extra += text_color_orange("\t    sudo chmod 644 /etc/issue\n")

        if (test_failed): 

            msg = "(1.7.1.5) Appropriate permissions for '/etc/issue' file need to be configured" 
            fail_l.append(msg)

            msg = color_symbol_debug() + text_color_yellow(" Configure security settings '/etc/issue' file\n\n")
            msg += msg_extra
            remediation_msg_l.append(msg)

        else:

            msg = "(1.7.1.5) '/etc/issue' file is configured with correct permissions" 
            pass_l.append(msg)
    else:
        pass

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #     (1.7.1.6) Ensure permissions on /etc/issue.net are configured       #
    ###########################################################################
    # /etc/issue.net needs to be:                                              
    # 1) Owned by root only                                                    
    # 2) Permissions need to be set to 644                                     

    test_failed = False

    if (os.path.isfile('/etc/issue.net')):

        attrs = os.stat('/etc/issue.net')

        uid = attrs.st_uid
        gid = attrs.st_gid

        msg_extra = ''

        if (uid != 0 or gid != 0):
            test_failed = True
            msg_extra += text_color_red("\tUID / GID should be limited to 0 / root user only\n\n")
            msg_extra += text_color_orange("\t  sudo chown root:root /etc/issue.net\n\n")

        perm = oct(attrs.st_mode)
        user_perm = int(perm[-3])
        group_perm = int(perm[-2])
        other_perm = int(perm[-1])

        if (not (user_perm == 6 and group_perm == 4 and other_perm == 4)):
            test_failed = True
            msg_extra += text_color_red("\tPermissions need to be set to 644\n\n")
            msg_extra += text_color_orange("\t  sudo chmod 644 /etc/issue.net\n")

        if (test_failed): 
            msg = "(1.7.1.6) Appropriate permissions for '/etc/issue.net' file need to be configured" 
            fail_l.append(msg)

            msg = color_symbol_debug() + text_color_yellow(" Configure security settings for '/etc/issue.net' file\n\n")
            msg += msg_extra
            remediation_msg_l.append(msg)

        else:

            msg = "(1.7.1.6) '/etc/issue.net' file is configured with correct permissions" 
            pass_l.append(msg)

    else:
        pass

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #              (1.7.2) Ensure GDM login banner is configured              #
    ###########################################################################

    fp = '/etc/gdm3/greeter.dconf-defaults'

    if (os.path.isfile(fp)):

        l1 = "[org/gnome/login-screen]"
        l2 = "banner-message-enable=true"
        l3 = "banner-message-text"

        l1_pass = False
        l2_pass = False
        l3_pass = False

        output = read_from_file(fp, ['#'])

        if (not output[0]):

            pass

        else:
            
            output = remove_all_elements_from_list(output[1], starts_with_l=['#'])

            for item in output:

                if (item.find(l1) == 0):
                    l1_pass = True
                elif (item.strip(l2) == 0):
                    l2_pass = True
                elif (item.strip(l3) == 0):
                    l3_pass = True

            if (l1_pass and l2_pass and l3_pass):

                msg = '(1.7.2) GDM login banner is configured properly'
                pass_l.append(msg)

            else:

                msg = '(1.7.2) GDM configuration error detected'
                fail_l.append(msg)

                msg = color_symbol_debug() + text_color_yellow(' Configure GDM, edit /etc/gdm3/greeter.dconf-defaults with the following:\n\n')
                msg += text_color_green('\t  [org/gnome/login-screen]\n\n')
                msg += text_color_green('\t  banner-message-enable=true\n\n')
                msg += text_color_green("\t  banner-message-text='Authorized uses only. All activity may be monitored and reported.'\n")
                remediation_msg_l.append(msg)
    else:
        pass

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #             (2.1.1) Ensure chargen services are not enabled             #
    ###########################################################################

    cmd = 'grep -R "^chargen" /etc/inetd.*'

    stdout, stderr, rc = run_cmd(cmd) 

    if (rc == 0): 

        msg = '(2.1.1) Chargen services need to be disabled' 
        fail_l.append(msg)

        txt = color_symbol_debug() + text_color_yellow(' Disable chargen services\n\n')
        txt += text_color_green('\t  Comment out any lines starting with chargen from /etc/inetd.conf and /etc/inetd.d/*\n')
        remediation_msg_l.append(txt)

    else:

        msg = '(2.1.1) Chargen service are disabled' 
        pass_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #                (2.1.2) Ensure daytime services are not enabled          #
    ###########################################################################

    cmd = 'grep -R "^daytime" /etc/inetd.*'

    stdout, stderr, rc = run_cmd(cmd) 

    if (rc == 0): 
        msg = '(2.1.2) Daytime services need to be disabled' 
        fail_l.append(msg)

        txt = color_symbol_debug() + text_color_yellow(' Disable Daytime Services, ' + \
                'comment out any lines starting with daytime from /etc/inetd.conf and /etc/inetd.d/*\n')

        remediation_msg_l.append(txt)

    else:
        msg = '(2.1.2) Daytime services are disabled' 
        pass_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #             (2.1.3) Ensure discard services are not enabled             #
    ###########################################################################

    cmd = 'grep -R "^discard" /etc/inetd.*'

    stdout, stderr, rc = run_cmd(cmd) 

    if (rc == 0): 

        msg = '(2.1.3) Discard services need to be disabled' 
        fail_l.append(msg)

        txt = color_symbol_debug() + text_color_yellow('Disable discard services, ' + \
                'comment out any lines starting with discard ' + \
                'from /etc/inetd.conf and /etc/inetd.d/*\n')

        remediation_msg_l.append(txt)

    else:
        msg = '(2.1.3) Discard services are disabled' 
        pass_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #              (2.1.4) Ensure echo services are not enabled               #
    ###########################################################################

    cmd = 'grep -R "^echo" /etc/inetd.*'

    stdout, stderr, rc = run_cmd(cmd) 

    if (rc == 0): 

        msg = '(2.1.4) Echo services need to be disabled' 
        fail_l.append(msg)

        txt = color_symbol_debug() + text_color_yellow(' Disable echo service, comment out' + \
                'any lines starting with echo from /etc/inetd.conf and /etc/inetd.d/*\n')

        remediation_msg_l.append(txt)

    else:
        msg = '(2.1.4) Echo services are disabled' 
        pass_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #             (2.1.5) Ensure time services are not enabled                #
    ###########################################################################

    cmd = 'grep -R "^time" /etc/inetd.*'

    stdout, stderr, rc = run_cmd(cmd) 

    if (rc == 0): 

        msg = '(2.1.5) Time services need to be disabled' 
        fail_l.append(msg)

        txt = color_symbol_debug() + text_color_yellow(' Disable time services, ' + \
                'comment out any lines starting with time from /etc/inetd.conf ' + \
                'and /etc/inetd.d/*\n')

        remediation_msg_l.append(txt)


    else:
        msg = '(2.1.5) Time services are disabled' 
        pass_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #                 (2.1.6) Ensure rsh server is not enabled                #
    ###########################################################################

    cmd1 = 'grep -R "^shell" /etc/inetd.*'
    cmd2 = 'grep -R "^login" /etc/inetd.*'
    cmd3 = 'grep -R "^exec" /etc/inetd.*'

    stdout, stderr, rc1 = run_cmd(cmd1) 
    stdout, stderr, rc2 = run_cmd(cmd2) 
    stdout, stderr, rc3 = run_cmd(cmd2) 

    if (rc1 == 0 or rc2 == 0 or rc3 == 0): 

        msg = '(2.1.6) Remote Shell services need to be disabled' 
        fail_l.append(msg)

        txt = color_symbol_debug() + text_color_yellow('  Disable rsh server, ' + \
                'comment out any lines starting with shell, login or exec ' + \
                'from /etc/inetd.conf and /etc/inetd.d/*\n')

        remediation_msg_l.append(txt)

    else:
        msg = '(2.1.6) Remote shell services are disabled' 
        pass_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #                (2.1.7) Ensure talk server is not enabled                #
    ###########################################################################

    cmd1 = 'grep -R "^talk" /etc/inetd.*'
    cmd2 = 'grep -R "^ntalk" /etc/inetd.*'

    stdout, stderr, rc1 = run_cmd(cmd1) 
    stdout, stderr, rc2 = run_cmd(cmd2) 

    if (rc1 == 0 or rc2 == 0): 

        msg = '(2.1.7) Talk service needs to be disabled' 
        fail_l.append(msg)

        txt = color_symbol_debug() + text_color_yellow('  Disable talk server, ' + \
                'comment out any lines starting with talk or ntalk ' + \
                'from /etc/inetd.conf and /etc/inetd.d/*\n')

        remediation_msg_l.append(txt)

    else:

        msg = '(2.1.7) Talk services are disabled' 
        pass_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #             (2.1.8) Ensure telnet server is not enabled                 #
    ###########################################################################

    cmd1 = 'grep -R "^telnet" /etc/inetd.*'

    stdout, stderr, rc1 = run_cmd(cmd1) 

    if (rc1 == 0): 

        msg = '(2.1.8) Telnet service needs to be disabled' 
        fail_l.append(msg)

        txt = color_symbol_debug() + text_color_yellow(' Disable telnet service, ' + \
                'comment out any lines starting with telnet ' + \
                'from /etc/inetd.conf and /etc/inetd.d/*\n')

        remediation_msg_l.append(txt)


    else:
        msg = '(2.1.8) Telnet services are disabled' 
        pass_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #               (2.1.9) Ensure tftp server is not enabled                 #
    ###########################################################################

    cmd1 = 'grep -R "^tftp" /etc/inetd.*'

    stdout, stderr, rc1 = run_cmd(cmd1) 

    if (rc1 == 0): 

        msg = '(2.1.9) Tftp service needs to be disabled' 
        fail_l.append(msg)

        txt = color_symbol_debug() + text_color_yellow(' Tftp server needs to be disabled, ' + \
                'comment out any lines starting with tftp ' + \
                'from /etc/inetd.conf and /etc/inetd.d/*\n')

        remediation_msg_l.append(txt)

    else:
        msg = '(2.1.9) Tftp services are disabled' 
        pass_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #                  (2.1.10) Ensure xinetd is not enabled                  #
    ###########################################################################

    cmd1 = 'ls /etc/rc*.d | grep xinetd'

    stdout, stderr, rc1 = run_cmd(cmd1) 

    if (rc1 == 0): 

        msg = '(2.1.10) Xinetd service needs to be disabled' 
        fail_l.append(msg)

        txt = color_symbol_debug() + text_color_yellow('  Disable xinetd:\n\n')
        cmd1 = text_color_orange('\t  systemctl disable xinetd\n\n')
        cmd2 = text_color_orange('\t  update-rc.d xinetd disable\n\n')
        txt += cmd1
        txt += cmd2
        remediation_msg_l.append(txt)

    else:
        msg = '(2.2.1.2) Xinetd services are disabled' 
        pass_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #             (2.2.1.1) Ensure time synchronization is enabled            #
    ###########################################################################

    output = pkgmgr_search_if_installed('ntp')

    if (not output): 

        msg = '(2.2.1.1) NTP services need to be enabled' 
        fail_l.append(msg)

        msg = color_symbol_debug() + text_color_yellow(' Enable Time Synchronization by installing ntp:\n\n')
        cmd = text_color_orange('\t  %s\n\n' % pkgmgr_print_install_cmd('ntp'))
        msg += cmd
        remediation_msg_l.append(msg)

    else:
        msg = '(2.2.1.1) NTP services are enabled' 
        pass_l.append(msg)


    ###########################################################################
    #                    (2.2.1.2) Ensure NTP is configured                   #
    ###########################################################################
    #                                                                          
    #TODO: Requires more thorough testing                                      
    #TODO: Remediation (pg#172)                                                

    cmd1 = 'grep "^restrict" /etc/ntp.conf'
    cmd2 = 'grep -E "^(server|pool)" /etc/ntp.conf'
    cmd3 = 'grep "^OPTIONS" /etc/sysconfig/ntpd'
    cmd4 = 'grep "^NTPD_OPTIONS" /etc/sysconfig/ntp'
    cmd5 = 'grep "RUNASUSER=ntp" /etc/init.d/ntp'

    stdout1, stderr1, rc1 = run_cmd(cmd1) 
    stdout2, stderr2, rc2 = run_cmd(cmd2) 
    stdout3, stderr3, rc3 = run_cmd(cmd3) 
    stdout4, stderr4, rc4 = run_cmd(cmd4) 
    stdout5, stderr5, rc5 = run_cmd(cmd5) 

    check_passed = True

    if (rc1 != 0 or rc2 != 0 or rc3 != 0):

        check_passed = False
        msg = '(2.2.1.2) NTP needs to be configured properly'
        fail_l.append(msg)

    elif (rc1 == 0 or check_passed):

        found_error = False

        error_msg = ''

        params = ['default', 'kod', 'nomodify', 'notrap', 'nopeer', 'noquery']
        stdout = [x.split() for x in stdout1.splitlines()]

        for line in stdout:

            result = check_if_all_element_in_list(line, params)

            if (not result[0]):
                found_error = True
                check_passed = False
                txt = ''

                for item in result[1]:
                    txt += '%s ' % item

                error_msg += text_color_green('\t  %s\n\n' % txt)

        if (found_error):
            msg = '(2.2.1.2) NTP needs to be configured properly'
            fail_l.append(msg)

            msg = color_symbol_debug() + text_color_yellow(' NTP service missing the following parameters:\n\n')
            msg += error_msg
            remediation_msg_l.append(msg)

    elif (rc2 != 0 or check_passed):
            check_passed = False
            msg = '(2.2.1.2) No remote servers configured for NTP'
            fail_l.append(msg)

    elif (rc3 == 0 or rc4 == 0 or check_passed): 

        if (rc3):
            stdout = stdout3
        elif (rc4):
            stdout = stdout4

        stdout = stdout.splitlines()

        found = False

        for line in stdout:

            if ("-u ntp:ntp" in line):
                check_passed = False
                found = True

        if (not found):
            msg = '(2.2.1.2) NTP service needs to be run as ntp user' 
            fail_l.append(msg)

    elif (rc5 == 0 and check_passed):

        stdout = stdout5.splitlines()

        found = False

        for line in stdout:

            if ("RUNASUSER=ntp" in line.strip()):
                check_passed = False
                found = True

        if (not found):
            msg = '(2.2.1.2) NTP service needs to be run as ntp user' 
            fail_l.append(msg)

    if (check_passed):
        msg = '(2.2.1.2) NTP server configuration is correct' 
        pass_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #                   (2.2.1.3) Ensure chrony is configured                 #
    ###########################################################################

    cmd1 = "ps -ef | grep chronyd"

    stdout, stderr, rc1 = run_cmd(cmd1) 

    chronyd_service_configured = False

    tmp = stdout.splitlines()

    for item in tmp:

        _item = item.split()

        if (_item[7] == 'chronyd' and item[0] == 'chronyd'):
            chronyd_service_configured = True
            break

    if (rc1 == 0 and chronyd_service_configured): 

        msg = '(2.2.1.3) Chrony service is configured'
        pass_l.append(msg)

    else:

        msg = '(2.2.1.3) Chrony service needs to be configured' 
        fail_l.append(msg)

        msg = color_symbol_debug() + text_color_yellow(' Configure chrony service, add or edit server or pool lines to /etc/chrony.conf: \n\n')
        msg += text_color_green('\t  server <remote-server>\n')
        remediation_msg_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #             (2.2.1.4)  Ensure systemd-timesyncd is configured           #
    ###########################################################################

    cmd1 = "systemctl is-enabled systemd-timesyncd.service"
    cmd2 = "timedatectl status"

    stdout1, stderr1, rc1 = run_cmd(cmd1) 
    stdout2, stderr2, rc2 = run_cmd(cmd2) 

    if (rc1 != 0): 

        msg = '(2.2.1.4) systemd-timesyncd service needs to be configured & enabled' 
        fail_l.append(msg)

        msg = color_symbol_debug() + text_color_yellow('  Edit the file /etc/systemd/timesyncd.conf:\n\n')
        msg += text_color_green('\t  NTP=0.debian.pool.ntp.org 1.debian.pool.ntp.org\n\n')
        msg += text_color_green('\t  FallbackNTP=2.debian.pool.ntp.org 3.debian.pool.ntp.org\n\n')
        msg += text_color_green('\t  RootDistanceMax=1 #should be In Accordence With Local Policy\n\n')

        msg += color_symbol_debug() + text_color_yellow('  Enable the service:\n\n')
        msg += text_color_orange('\t  systemctl start systemd-timesyncd.service\n\n')
        msg += text_color_orange('\t  timedatectl set-ntp true\n')

    else:

        if (rc2 != 0):

            msg = '(2.2.1.4) systemd-timesyncd service is not enabled'
            fail_l.append(msg)

            msg = color_symbol_debug() + text_color_yellow(' Configure Systemd Timesync service:\n\n')
            msg += text_color_orange('\t  systemctl start systemd-timesyncd.service\n\n')
            msg += text_color_orange('\t  timedatectl set-ntp true\n')
            remediation_msg_l.append(msg)

        else:

            msg = '(2.2.1.4) systemd-timesyncd service is configured'
            pass_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #            (2.2.2) Ensure X Window System is not installed              #
    ###########################################################################

    output1 = pkgmgr_search_if_installed('xorg-x11*')
    output2 = pkgmgr_search_if_installed('xserver-xorg*')

    if (output1 or output2):

        msg = '(2.2.2) X Windows System (xorg) is not installed (reduce attack surface)'
        pass_l.append(msg)

    else:

        msg = '(2.2.2) X Windows System (xorg) needs to be removed (reduce attack surface)'
        fail_l.append(msg)

        msg = color_symbol_debug() + text_color_yellow(' Uninstall xorg server:\n\n')
        msg += text_color_orange('\t  %s\n\n' % pkgmgr_print_uninstall_cmd('xorg-x11*'))
        msg += text_color_orange('\t  %s\n' % pkgmgr_print_uninstall_cmd('xserver-xorg*'))
        remediation_msg_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #                2.2.3 Ensure Avahi Server is not enabled                 #
    ###########################################################################

    cmd1 = "systemctl is-enabled avahi-daemon"

    stdout1, stderr1, rc1 = run_cmd(cmd1) 

    if (rc1 == 0): 

        msg = '(2.2.3) Automatic discovery of network service (avahi-daemon) needs to be disabled'
        fail_l.append(msg)

        msg = color_symbol_debug() + text_color_yellow(' Disable avahid daemon service:\n\n')
        msg += text_color_orange('\t  sudo systemctl disable avahi-daemon\n') 
        remediation_msg_l.append(msg)

    else:

        msg = '(2.2.3) Avahi daemon is disabled'
        pass_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #                    2.2.4 Ensure CUPS is not enabled                     #
    ###########################################################################

    cmd1 = "systemctl is-enabled cups"

    stdout1, stderr1, rc1 = run_cmd(cmd1) 

    if (rc1 == 0): 

        msg = '(2.2.4) Printing services (cups) needs to be disabled\n\n'
        fail_l.append(msg)

        msg = color_symbol_debug() + text_color_yellow(' Disable Printing services:\n\n')
        msg += text_color_orange('\t   sudo systemctl disable cups\n') 
        remediation_msg_l.append(msg)

    else:

        msg = '(2.2.4) Cups service is disabled'
        pass_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #                 2.2.5 Ensure DHCP Server is not enabled                 #
    ###########################################################################

    cmd1 = "systemctl is-enabled dhcp"

    stdout1, stderr1, rc1 = run_cmd(cmd1) 

    if (rc1 == 0): 

        msg = '(2.2.5) DHCP service needs to be disabled'
        fail_l.append(msg)

        msg = color_symbol_debug() + text_color_yellow(' Disable DHCP service:\n\n')
        msg += text_color_orange('\t  sudo systemctl disable dhcp\n') 
        remediation_msg_l.append(msg)

    else:

        msg = '(2.2.5) DHCP service is disabled'
        pass_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #                 2.2.6 Ensure LDAP Server is not enabled                 #
    ###########################################################################

    cmd1 = "systemctl is-enabled slapd"

    stdout1, stderr1, rc1 = run_cmd(cmd1) 

    if (rc1 == 0): 

        msg = '(2.2.6) LDAP server needs to be disabled'
        fail_l.append(msg)

        msg = color_symbol_debug() + text_color_yellow(' Disable LDAP service:\n\n')
        msg += text_color_orange('\t  sudo systemctl disable slapd\n') 
        remediation_msg_l.append(msg)

    else:

        msg = '(2.2.6) LDAP server is disabled'
        pass_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #                  2.2.7 Ensure NFS & RPC are not enabled                 #
    ###########################################################################

    cmd1 = "systemctl is-enabled nfs"
    cmd2 = "systemctl is-enabled rpcbind"

    stdout1, stderr1, rc1 = run_cmd(cmd1) 
    stdout2, stderr2, rc2 = run_cmd(cmd2) 

    if (rc1 == 0 or rc2 == 0): 

        msg = '(2.2.7) NFS & RPC services need to be disabled'
        fail_l.append(msg)

        error_msg = '' 

        if (rc1 == 0):
            error_msg += text_color_orange('\t  sudo systemctl disable nfs\n') 

        if (rc2 == 0):
            error_msg += text_color_orange('\t  sudo systemctl disable rpcbind\n') 

        msg = color_symbol_debug() + text_color_yellow(' Disable NFS & RPC services:\n\n')
        msg += error_msg

        remediation_msg_l.append(msg)

    else:

        msg = '(2.2.7) NFS & RPC services are disabled'
        pass_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #                  2.2.8 Ensure DNS server is not enabled                 #
    ###########################################################################

    cmd1 = "systemctl is-enabled named"

    stdout1, stderr1, rc1 = run_cmd(cmd1) 

    if (rc1 == 0): 

        msg = '(2.2.8) DNS server needs to be removed'
        fail_l.append(msg)

        msg = color_symbol_debug() + text_color_yellow(' Disable DNS service:\n\n')
        msg += text_color_orange('\t  sudo systemctl disable named\n') 
        remediation_msg_l.append(msg)

    else:

        msg = '(2.2.8) DNS server is disabled'
        pass_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #                  2.2.9 Ensure FTP server is not enabled                 #
    ###########################################################################

    cmd1 = "systemctl is-enabled vsftpd"

    stdout1, stderr1, rc1 = run_cmd(cmd1) 

    if (rc1 == 0): 

        msg = '(2.2.9) FTP server (vsftpd) needs to be disabled'
        fail_l.append(msg)

        msg = color_symbol_debug() + text_color_yellow(' Disable DNS service:\n\n')
        msg += text_color_orange('\t  sudo systemctl disable vsftpd\n') 
        remediation_msg_l.append(msg)

    else:

        msg = '(2.2.9) FTP server (vsftpd) is disabled'
        pass_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #                  2.2.10 Ensure HTTP server is not enabled               #
    ###########################################################################

    cmd1 = "systemctl is-enabled httpd"

    stdout1, stderr1, rc1 = run_cmd(cmd1) 

    if (rc1 == 0): 

        msg = '(2.2.10) HTTP server needs to be disabled'
        fail_l.append(msg)

        msg = color_symbol_debug() + text_color_yellow(' Disable HTTP service:\n\n')
        msg += text_color_orange('\t    sudo systemctl disable httpd\n') 
        remediation_msg_l.append(msg)


    else:

        msg = '(2.2.10) HTTP server is disabled'
        pass_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #             2.2.11 Ensure IMAP & POP3 server is not enabled             #
    ###########################################################################

    cmd1 = "systemctl is-enabled dovecot"

    stdout1, stderr1, rc1 = run_cmd(cmd1) 

    if (rc1 == 0): 

        msg = '(2.2.11) Dovecot service needs to be disabled'
        fail_l.append(msg)

        msg = color_symbol_debug() + text_color_yellow(' Disable IMAP & POP3 service:\n\n')
        msg += text_color_orange('\t    sudo systemctl disable dovecot\n') 
        remediation_msg_l.append(msg)

    else:

        msg = '(2.2.11) Dovecot service is disabled'
        pass_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #                   2.2.12 Ensure Samba is not enabled                    #
    ###########################################################################

    cmd1 = "systemctl is-enabled smb"

    stdout1, stderr1, rc1 = run_cmd(cmd1) 

    if (rc1 == 0): 

        msg = '(2.2.12) Samba service needs to be disabled'
        fail_l.append(msg)

        msg = color_symbol_debug() + text_color_yellow(' Disable Samba service:\n\n')
        msg += text_color_orange('\t  sudo systemctl disable smb\n') 
        remediation_msg_l.append(msg)

    else:

        msg = '(2.2.12) Samba service is disabled'
        pass_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #             2.2.13 ensure http proxy server is not enabled              #
    ###########################################################################

    cmd1 = "systemctl is-enabled squid"

    stdout1, stderr1, rc1 = run_cmd(cmd1) 

    if (rc1 == 0): 

        msg = '(2.2.13) http proxy server (squid) needs to be disabled'
        fail_l.append(msg)

        msg = color_symbol_debug() + text_color_yellow(' Disable Http Proxy service:\n\n')
        msg += text_color_orange('\t  sudo systemctl disable squid\n') 
        remediation_msg_l.append(msg)

    else:

        msg = '(2.2.13) http proxy server (squid) is disabled'
        pass_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #                  2.2.14 Ensure SNMP Server is not enabled               #
    ###########################################################################

    cmd1 = "systemctl is-enabled snmpd"

    stdout1, stderr1, rc1 = run_cmd(cmd1) 

    if (rc1 == 0): 

        msg = '(2.2.14) SNMP server needs to be disabled'
        fail_l.append(msg)

        msg = color_symbol_debug() + text_color_yellow(' Disable SNMP service:\n\n')
        msg += text_color_orange('\t  sudo systemctl disable snmpd\n') 
        remediation_msg_l.append(msg)

    else:

        msg = '(2.2.14) SNMP server is disabled'
        pass_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #            2.2.15 Ensure mail transfer agent is configured              #
    ###########################################################################

    cmd1 = "ss -lntu | grep -E ':25\s' | grep -E -v '\s(127.0.0.1|::1):25\s'"

    stdout1, stderr1, rc1 = run_cmd(cmd1) 

    if (rc1 == 1): 

        msg = '(2.2.15) Mail transfer agent needs to be configured'
        fail_l.append(msg)

        msg = color_symbol_debug() + text_color_yellow(' Configure Mail transfer agent:\n\n')
        msg += text_color_yellow('\tEdit /etc/postfix/main.cf and add the following line to the RECEIVING MAIL section\n\n')
        msg += text_color_green('\t  inet_interfaces = loopback-only\n\n') 
        msg += text_color_yellow('\tRestart the service\n\n')
        msg += text_color_orange('\t  sudo systemctl restart postfix\n') 
        remediation_msg_l.append(msg)

    else:

        msg = '(2.2.15) Mail transfer agent is configured'
        pass_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #              2.2.16 Ensure rsync service is not enabled                 #
    ###########################################################################

    cmd1 = "systemctl is-enabled rsyncd"

    stdout1, stderr1, rc1 = run_cmd(cmd1) 

    if (rc1 == 0): 

        msg = '(2.2.16) Rsync service poses a security risk (unencrypted protocols), needs to be disabled'
        fail_l.append(msg)

        msg = color_symbol_debug() + text_color_yellow(' Disable Rsync service:\n\n')
        msg += text_color_orange('\t  sudo systemctl disable rsyncd\n') 
        remediation_msg_l.append(msg)

    else:

        msg = '(2.2.16) Rsync service is disabled'
        pass_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #                 2.2.17 Ensure NIS Server is not enabled                 #
    ###########################################################################

    cmd1 = "systemctl is-enabled ypserv"

    stdout1, stderr1, rc1 = run_cmd(cmd1) 

    if (rc1 == 0): 

        msg = '(2.2.17) NIS server is vulnerable to buffer overflow, DoS, etc. needs to be disabled'
        fail_l.append(msg)

        msg = color_symbol_debug() + text_color_yellow(' Disable NIS server:\n\n')
        msg += text_color_orange('\t sudo systemctl disable ypserv\n') 
        remediation_msg_l.append(msg)

    else:

        msg = '(2.2.17) NIS server is disabled'
        pass_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #                 2.3.1 Ensure NIS Client needs to be removed             #
    ###########################################################################

    output = pkgmgr_search_if_installed('ypbind')

    if (output): 

        msg = '(2.3.1) NIS client is vulnerable to buffer overflow, DoS, etc. needs to be disabled'
        fail_l.append(msg)

        msg = color_symbol_debug() + text_color_yellow(' Disable NIS client:\n\n')
        msg += text_color_orange('\t  %s\n' % pkgmgr_print_uninstall_cmd('ypbind')) 
        remediation_msg_l.append(msg)

    else:

        msg = '(2.3.1) NIS client is disabled'
        pass_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #                 2.3.2 Ensure RSH Client is not installed                #
    ###########################################################################

    output = pkgmgr_search_if_installed('rsh')

    if (output): 

        msg = '(2.3.2) RSH client has security vulns so needs to be disabled'
        fail_l.append(msg)

        msg = color_symbol_debug() + text_color_yellow(' Disable RSH client:\n\n')
        msg += text_color_orange('\t  %s\n' % pkgmgr_print_uninstall_cmd('rsh')) 
        remediation_msg_l.append(msg)

    else:

        msg = '(2.3.2) RSH client is disabled'
        pass_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #                 2.3.3 Ensure Talk Client is not installed               #
    ###########################################################################

    output = pkgmgr_search_if_installed('talk')

    if (not output): 

        msg = '(2.3.3) Talk client has security vulns (unencrypted protocols) so needs to be disabled'
        fail_l.append(msg)

        msg = color_symbol_debug() + text_color_yellow(' Disable Talk client:\n\n')
        msg += text_color_orange('\t  %s\n' % pkgmgr_print_uninstall_cmd('talk')) 
        remediation_msg_l.append(msg)

    else:

        msg = '(2.3.3) Talk client is not installed'
        pass_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #                 2.3.4 Ensure Telnet Client is not installed             #
    ###########################################################################

    output = pkgmgr_search_if_installed('telnet')

    if (not output): 

        msg = '(2.3.4) Telnet client is insecure & unencrypted so needs to be removed'
        fail_l.append(msg)

        msg = color_symbol_debug() + text_color_yellow(' Disable Telnet client:\n\n')
        msg += text_color_orange('\t  %s\n' % pkgmgr_print_uninstall_cmd('telnet')) 
        remediation_msg_l.append(msg)

    else:

        msg = '(2.3.4) Telnet client is not installed'
        pass_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #                 2.3.5 Ensure LDAP Client is not installed               #
    ###########################################################################

    output = pkgmgr_search_if_installed('openldap-clients')

    if (not output): 

        msg = '(2.3.5) Openldap client is insecure & unencrypted so needs to be removed'
        fail_l.append(msg)

        msg = color_symbol_debug() + text_color_yellow(' Disable LDAP client:\n\n')
        msg += text_color_orange('\t  %s\n' % pkgmgr_print_uninstall_cmd('openldap-clients')) 
        remediation_msg_l.append(msg)

    else:

        msg = '(2.3.5) Openldap client is not installed'
        pass_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #                        CIS Network Stack Hardening                      #
    ###########################################################################

    
    if (len(sysctl_configs_validator) == 0):

        print(text_error('(3.x.x) Skipping CIS Network Configuration Checks (no validator found)'))

    else:

        for item in sysctl_configs_validator:

            # configs = [CIS#, Desc, [sysctl flags]]

            flag_l = item[2]

            desc = item[1]

            # cis_num = item[0]

            pass_test = True

            for flag in flag_l:

                output = flag.split('=')

                param = output[0]
                val = output[1]

                if (not skip_sysctl_utility_checks):

                    cmd = 'sysctl %s' % param

                    stdout, stderr, rc = run_cmd(cmd)

                    if (rc == 0):

                        _val = stdout.split('=')[1].strip()

                        if (val != _val):
                            pass_test = False
                            flags_inactive.append(flag)

                #Comparing with user defined flags from config
                else:

                    if (flag in sysctl_configs_user):
                        pass_test = True
                    else:
                        pass_test = False
                        flags_inactive.append(flag)

            if (pass_test):
                pass_l.append('(3.x.x) %s is enabled' % desc.capitalize())
            else:
                msg = '(3.x.x) %s needs to be disabled' % desc.capitalize()
                fail_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #             3.3.1 Ensure tcp wrappers is installed (unscored)           #
    ###########################################################################
    
    #output1 = pkgmgr_search_if_installed('tcp_wrappers')
    #output2 = pkgmgr_search_if_installed('tcpd')

    #if (not (output1 or output2)): 

    #    msg = '(3.3.1) TCP Wrappers package needs to be installed'
    #    fail_l.append(msg)

    #    msg = color_symbol_debug() + text_color_yellow(' Install Tcp wrappers:\n\n')
    #    msg += text_color_orange('\t  %s\n' % pkgmgr_print_install_cmd('tcpd')) 
    #    msg += text_color_orange('\t  %s\n' % pkgmgr_print_install_cmd('tcp_wrappers')) 
    #    remediation_msg_l.append(msg)

    #else:

    #    msg = '(3.3.1) TCP Wrappers is installed'
    #    pass_l.append(msg)


    #The following check is unscored, leaving it out here cos I put in work :(

    ###########################################################################
    #                3.3.2 Ensure /etc/hosts.allow is configured              #
    # This check requires user validation of config so it's prioritized first #
    ###########################################################################
    
    #test_failed = False

    #f = '/etc/hosts.allow' 

    #if (os.path.isfile(f)):

    #    data = read_from_file(f, ['','#','\n'])
    #    
    #    if (data[0]):
    #        _data = remove_all_elements_from_list(data[1], starts_with_l=['#'])

    #        if (len(_data) == 0):
    #            test_failed = True
    #        else:
    #            msg = color_symbol_question() + text_color_yellow(' Does the' + \
    #                    'following configuration have IP addresses listed for ' + \
    #                    'required services?\n\n')

    #            for item in _data:
    #                msg += text_color_green('\t  %s\n' % item) 

    #            print(msg)

    #            val = prompt_yes_no()

    #            if (val):
    #                pass_l.append("'/etc/hosts.allow' file is configured correctly")
    #            else:
    #                test_failed = True

    #                msg = color_symbol_debug() + text_color_yellow(" Need to Configure '/etc/hosts.allow' file \n\n")
    #                msg += text_color_magenta('\tUse the following command, where net/mask represents IP block:\n\n') 
    #                msg += text_color_orange('\t  echo "ALL: <net>/<mask>, <net>/<mask>, ..." >/etc/hosts.allow\n') 
    #                remediation_msg_l.append(msg)
    #else:
    #    test_failed = True

    #if (test_failed):
    #    fail_l.append("Need to configure '/etc/hosts.allow' file to permit authorized hosts only")


    ###########################################################################
    #        3.3.4 Ensure permissions on /etc/hosts.allow are configured      #
    ###########################################################################

    fp = '/etc/hosts.allow'

    test_failed = False

    if (os.path.isfile(fp)):

        attrs = os.stat(fp)
        perm = oct(attrs.st_mode)
        user_perm = int(perm[-3])
        group_perm = int(perm[-2])
        other_perm = int(perm[-1])

        if (attrs.st_uid == 0 and attrs.st_gid == 0 and \
                user_perm >= 6 and group_perm == 4 and other_perm == 4):
            msg = "(3.3.4) File '%s' is configured with correct permissions" % fp
            pass_l.append(msg)
        else:
            test_failed = True

    else:

        test_failed = True

    if (test_failed):
        msg = "(3.3.4) File '%s' needs to be configured with correct permissions" % fp
        fail_l.append(msg)

        error_msg = color_symbol_debug() + text_color_yellow(" Configure permissions for '%s' file\n" % fp)

        cmd = "  sudo chown root:root %s\n" % fp 
        error_msg += "\n\t" + text_color_orange(cmd)
        cmd = "  sudo chmod og-rwx %s\n" % fp 
        error_msg += "\t" + text_color_orange(cmd)
        remediation_msg_l.append(error_msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #        3.3.5 Ensure permissions on /etc/hosts.deny are configured       #
    ###########################################################################

    fp = '/etc/hosts.deny'

    test_failed = False

    if (os.path.isfile(fp)):

        attrs = os.stat(fp)
        perm = oct(attrs.st_mode)
        user_perm = int(perm[-3])
        group_perm = int(perm[-2])
        other_perm = int(perm[-1])

        if (attrs.st_uid == 0 and attrs.st_gid == 0 and \
                user_perm >= 6 and group_perm == 4 and other_perm == 4):
            msg = "(3.3.5) File '%s' is configured with correct permissions" % fp
            pass_l.append(msg)
        else:
            test_failed = True

    else:

        test_failed = True

    if (test_failed):
        msg = "(3.3.5) File '%s' needs to be configured with correct permissions" % fp
        fail_l.append(msg)

        error_msg = color_symbol_debug() + text_color_yellow(" Configure permissions for '%s' file\n" % fp)

        cmd = "  sudo chown root:root %s\n" % fp 
        error_msg += "\n\t" + text_color_orange(cmd)
        cmd = "  sudo chmod og-rwx %s\n" % fp 
        error_msg += "\t" + text_color_orange(cmd)
        remediation_msg_l.append(error_msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #                       3.4.1 Ensure DCCP is disabled                     #
    ###########################################################################

    output = check_if_module_loaded('dccp')

    if (output[0]):
        msg = '(3.4.1) Module dccp is present, needs to be disabled in kernel'
        fail_l.append(msg)

        msg = color_symbol_debug() + text_color_yellow(" Disable module DCCP by " + \
                "adding the following line to '/etc/modprobe.d/dccp.conf'\n\n")
        msg += "\t  " + text_color_orange('install dccp /bin/true')
        remediation_msg_l.append(msg)

    else:
        msg = '(3.4.1) Module dccp is not present' 
        pass_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #                       3.4.2 Ensure SCTP is disabled                     #
    ###########################################################################

    output = check_if_module_loaded('sctp')

    if (output[0]):
        msg = '(3.4.2) Module sctp is present, needs to be disabled in kernel'
        fail_l.append(msg)

        msg = color_symbol_debug() + text_color_yellow(" Disable module SCTP by " + \
                "adding the following line to '/etc/modprobe.d/dccp.conf'\n\n")
        msg += "\t  " + text_color_orange('install sctp /bin/true')
        remediation_msg_l.append(msg)

    else:
        msg = '(3.4.2) Module sctp is not present' 
        pass_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #                       3.4.3 Ensure RDS is disabled                      #
    ###########################################################################

    output = check_if_module_loaded('rds')

    if (output[0]):
        msg = '(3.4.3) Module rds is present, needs to be disabled in kernel'
        fail_l.append(msg)

        msg = color_symbol_debug() + text_color_yellow(" Disable module rds by " + \
                "adding the following line to '/etc/modprobe.d/dccp.conf'\n\n")
        msg += "\t  " + text_color_orange('install rds /bin/true')
        remediation_msg_l.append(msg)

    else:
        msg = '(3.4.3) Module rds is not present' 
        pass_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #                       3.4.4 Ensure TIPC is disabled                     #
    ###########################################################################

    output = check_if_module_loaded('tipc')

    if (output[0]):
        msg = '(3.4.4) Module tipc is present, needs to be disabled in kernel'
        fail_l.append(msg)

        msg = color_symbol_debug() + text_color_yellow(" Disable module tipc by " + \
                "adding the following line to '/etc/modprobe.d/dccp.conf'\n\n")
        msg += "\t  " + text_color_orange('install tipc /bin/true')
        remediation_msg_l.append(msg)

    else:
        msg = '(3.4.4) Module tipc is not present' 
        pass_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #            3.5.1.1 Ensure IPv6 default deny firewall policy             #
    ###########################################################################

    test_failed = False
    passive_check = False

    paths = ['/usr/bin/', '/usr/sbin/', '/bin/', '/sbin/']
    output = check_if_files_are_valid(['ip6tables'], paths) 

    if (len(output[1]) != 0):
        passive_check = True

    if (passive_check):

        cmd1 = 'grep "\S*linux*" /boot/grub2/grub.cfg  | grep "ipv6.disable=1"'
        cmd2 = 'grep "\S*linux*" /boot/grub/grub.cfg  | grep "ipv6.disable=1"'

        stdout1, stderr1, rc1 = run_cmd(cmd1)
        stdout2, stderr2, rc2 = run_cmd(cmd2)

        if (rc1 == 0 or rc2 == 0):
            pass_l.append('IPv6 is set with default deny policy')
        else:
            test_failed = True
    else:

        cmd = "sudo ip6tables -L | grep -E 'INPUT|FORWARD|OUTPUT'"

        stdout, stderr, rc = run_cmd(cmd)

        if (rc == 0):

            l = stdout.splitlines()

            p1 = 'policy DROP'
            p2 = 'policy REJECT'

            policy_input_pass = False
            policy_forward_pass = False
            policy_output_pass = False

            for item in l:

                s1 = item.find('INPUT')
                s2 = item.find('FORWARD')
                s3 = item.find('OUTPUT')

                if (s1 >= 0):
                    if (item.find(p1) >= 0 or item.find(p2) >= 0):
                        policy_input_pass = True
                if (s2 >= 0):
                    if (item.find(p1) >= 0 or item.find(p2) >= 0):
                        policy_forward_pass = True
                if (s3 >= 0):
                    if (item.find(p1) >= 0 or item.find(p2) >= 0):
                        policy_output_pass = True

            if (policy_input_pass and policy_forward_pass and policy_output_pass):
                pass_l.append('(3.5.1.1) IPv6 is set with default deny policy')
            else:
                test_failed = True

        else:
            test_failed = True

    if (test_failed):

        fail_l.append('(3.5.1.1) IPv6 needs to be configured with default deny policy')

        msg = color_symbol_debug() + text_color_yellow(" Implement a " + \
                "default DROP policy for ipv6:\n\n")

        msg += "\t  " + text_color_orange('sudo ip6tables -P INPUT DROP\n')
        msg += "\t  " + text_color_orange('sudo ip6tables -P OUTPUT DROP\n')
        msg += "\t  " + text_color_orange('sudo ip6tables -P FORWARD DROP\n')
        remediation_msg_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #           3.5.1.2 Ensure IPv6 loopback traffic is configured            #
    ###########################################################################

    test_failed = False
    passive_check = False

    paths = ['/usr/bin/', '/usr/sbin/', '/bin/', '/sbin/']
    output = check_if_files_are_valid(['ip6tables'], paths) 

    if (len(output[1]) != 0):
        passive_check = True

    if (passive_check):

        cmd1 = 'grep "\S*linux*" /boot/grub2/grub.cfg  | grep "ipv6.disable=1"'
        cmd2 = 'grep "\S*linux*" /boot/grub/grub.cfg  | grep "ipv6.disable=1"'

        stdout1, stderr1, rc1 = run_cmd(cmd1)
        stdout2, stderr2, rc2 = run_cmd(cmd2)

        if (rc1 == 0 or rc2 == 0):
            pass_l.append('IPv6 is set with default deny policy')
        else:
            test_failed = True
    else:

        cmd1 = "sudo ip6tables -L INPUT -v -n"
        cmd2 = "sudo ip6tables -L OUTPUT -v -n"

        stdout1, stderr1, rc1 = run_cmd(cmd1)
        stdout2, stderr2, rc2 = run_cmd(cmd2)

        if (rc1 == 0 and rc2 == 0):

            l1 = []
            l2 = []

            l1_pass = False
            l2_pass = False

            tmp = stdout1.splitlines()
            l1 = tmp[2:]

            for line in l1:
                _line = line.split()

                if (_line[4] == 'lo' and _line[2] == 'ACCEPT'):
                    l1_pass = True

            tmp = stdout2.splitlines()
            l2 = tmp[2:]

            for line in l2:
                _line = line.split()

                if (_line[5] == 'lo' and _line[2] == 'ACCEPT'):
                    l2_pass = True

            if (l1_pass and l2_pass):
                pass_l.append('(3.5.1.2) IPv6 is configured to allow loopback traffic')
            else:
                test_failed = True

        else:
            test_failed = True

    if (test_failed):

        fail_l.append('(3.5.1.2) IPv6 needs to be configured to allow loopback traffic')

        msg = color_symbol_debug() + text_color_yellow(" Allow loopback traffic for ipv6:\n\n")
        msg += "\t  " + text_color_orange('sudo ip6tables -A INPUT -i lo -j ACCEPT\n')
        msg += "\t  " + text_color_orange('sudo ip6tables -A OUTPUT -o lo -j ACCEPT\n')
        msg += "\t  " + text_color_orange('sudo ip6tables -A INPUT -s ::1 -j DROP\n')
        remediation_msg_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #            3.5.2.1 Ensure IPv4 default deny firewall policy             #
    ###########################################################################

    test_failed = False
    passive_check = False

    cmd = "iptables -L | grep -E 'INPUT|FORWARD|OUTPUT'"

    stdout, stderr, rc = run_cmd(cmd)

    if (rc == 0):

        l = stdout.splitlines()

        p1 = 'policy DROP'
        p2 = 'policy REJECT'

        policy_input_pass = False
        policy_forward_pass = False
        policy_output_pass = False

        for item in l:

            s1 = item.find('INPUT')
            s2 = item.find('FORWARD')
            s3 = item.find('OUTPUT')

            if (s1 >= 0):
                if (item.find(p1) >= 0 or item.find(p2) >= 0):
                    policy_input_pass = True
            if (s2 >= 0):
                if (item.find(p1) >= 0 or item.find(p2) >= 0):
                    policy_forward_pass = True
            if (s3 >= 0):
                if (item.find(p1) >= 0 or item.find(p2) >= 0):
                    policy_output_pass = True

        if (policy_input_pass and policy_forward_pass and policy_output_pass):
            pass_l.append('(3.5.2.1) IPv4 is set with default deny policy')
        else:
            test_failed = True
    else:
        test_failed = True

    if (test_failed):

        fail_l.append('(3.5.2.1) IPv4 needs to be configured with default deny policy')

        msg = color_symbol_debug() + text_color_yellow(" Implement a default DROP policy for ipv4:\n\n")
        msg += "\t  " + text_color_orange('sudo iptables -P INPUT DROP\n')
        msg += "\t  " + text_color_orange('sudo iptables -P OUTPUT DROP\n')
        msg += "\t  " + text_color_orange('sudo iptables -P FORWARD DROP\n')
        remediation_msg_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #           3.5.2.2 Ensure loopback traffic is configured (IPv4)          #
    ###########################################################################

    test_failed = False
    passive_check = False

    cmd1 = "sudo ip6tables -L INPUT -v -n"
    cmd2 = "sudo ip6tables -L OUTPUT -v -n"

    stdout1, stderr1, rc1 = run_cmd(cmd1)
    stdout2, stderr2, rc2 = run_cmd(cmd2)

    if (rc1 == 0 and rc2 == 0):

        l1 = []
        l2 = []

        l1_pass = False
        l2_pass = False

        tmp = stdout1.splitlines()
        l1 = tmp[2:] # Skipping the first 2 lines as they're not relevant

        for line in l1:
            _line = line.split()

            if (_line[4] == 'lo' and _line[2] == 'ACCEPT'):
                l1_pass = True

        tmp = stdout2.splitlines()
        l2 = tmp[2:]

        for line in l2:
            _line = line.split()

            if (_line[5] == 'lo' and _line[2] == 'ACCEPT'):
                l2_pass = True

        if (l1_pass and l2_pass):
            pass_l.append('(3.5.2.2) IPv4 is configured to allow loopback traffic')
        else:
            test_failed = True

    else:
        test_failed = True

    if (test_failed):

        fail_l.append('(3.5.2.2) IPv4 needs to be configured to allow loopback traffic')

        msg = color_symbol_debug() + text_color_yellow(" Allow loopback traffic for ipv4:\n\n")
        msg += "\t  " + text_color_orange('sudo iptables -A INPUT -i lo -j ACCEPT\n')
        msg += "\t  " + text_color_orange('sudo iptables -A OUTPUT -o lo -j ACCEPT\n')
        msg += "\t  " + text_color_orange('sudo iptables -A INPUT -s 127.0.0.0/8 -j DROP\n')
        remediation_msg_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #          3.5.2.4 Ensure firewall rules exist for all open ports         #
    ###########################################################################

    cmd1 = "ss -4tunl | awk '{print $1, $5}'"
    cmd2 = "iptables -L INPUT -vn | awk '{print $10,$11}'"

    stdout1, stderr1, rc1 = run_cmd(cmd1)
    stdout2, stderr2, rc2 = run_cmd(cmd2)

    conn_l = stdout1.splitlines()[1:]

    # [(proto, port)]
    port_l = [] 
    rule_l = []

    failed_rules = []

    for i in range(len(conn_l)):

        item = conn_l[i].strip().split()

        if (len(item) != 2):
            continue
        else:
            proto = item[0]
            port = item[1].split(':')[1]
            
            port_l.append((proto, port))

    tmp = remove_all_elements_from_list(stdout2.splitlines(), ['\n',''], starts_with_l=[' '])

    for item in tmp:
        _item = item.split()
        proto = _item[0]
        port = _item[1].split(':')[1]

        rule_l.append((proto,port))

    for x in port_l:

        try:
            rule_l.index(x)
        except ValueError:
            failed_rules.append(x)

    # for item in failed_rules:
    #     print(item)

    if (len(failed_rules) == 0):
        pass_l.append('(3.5.2.4) Firewall rules exist for all open ports')
    else:
        msg = '(3.5.2.4) Need to apply firewall rules for the following open ports ( '

        for item in failed_rules:
            msg += '%s:%s ' % (item[0], item[1])

        msg += ')'

        fail_l.append(msg)

        msg = color_symbol_debug() + text_color_yellow(" Establish firewall rules for open ports\n\n")

        for rule in failed_rules:
            msg += "\t  " + text_color_orange('sudo iptables -A INPUT -p %s --dport %s -m state --state NEW -j ACCEPT\n' % (rule[0], rule[1]))

        remediation_msg_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #               3.5.3 Ensure iptables is installed                        #
    ###########################################################################

    output = pkgmgr_search_if_installed('iptables')

    if (output):
        pass_l.append('(3.5.3) iptables utility is installed')
    else:
        fail_l.append('(3.5.3) iptables utility needs to be installed')

        msg = color_symbol_debug() + text_color_yellow(" Run the following to install iptables: \n\n")
        msg += "\t  " + text_color_orange('%s\n' % (pkgmgr_print_install_cmd('iptables')))

        remediation_msg_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #           4.1.1.1 Ensure audit log storage size is configured           #
    ###########################################################################

    fp = '/etc/audit/auditd.conf'

    if (not os.path.isfile(fp)):

        fail_l.append('Auditd needs to be installed & log storage size has to be configured')

    else:

        cmd1 = 'grep max_log_file /etc/audit/auditd.conf'

        stdout1, stderr1, rc1 = run_cmd(cmd1)

        size = stdout1.splitlines()[0].split('=')[1].strip()

        output = convert_str_to_int(size)

        if (output[0]):

            pass_l.append('(4.1.1.1) Auditd log storage size is configured (%d MB)' % output[1][0])

        else:

            fail_l.append('(4.1.1.1) Auditd log storage size needs to be configured')

            msg = 'Configure Auditd log storage size by setting the following parameter in /etc/audit/auditd.conf'
            msg = color_symbol_debug() + text_color_yellow(" %s\n\n" % msg)
            msg += "\t  " + text_color_green('max_log_file = <MB>\n')

            remediation_msg_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #       4.1.1.2 Ensure system is disabled when audit logs are full        #
    ###########################################################################

    cmd1 = "grep -E 'space_left_action|action_mail_acct|admin_space_left_action' /etc/audit/auditd.conf"

    stdout1, stderr1, rc1 = run_cmd(cmd1)

    l = remove_all_elements_from_list(stdout1.splitlines(), starts_with_l=['#'])

    params_l = []

    num_passes = 0 # 3 checks need to be passed

    for item in l:

        _item = item.split('=')

        params_l.append(remove_whitespace_from_list(_item))
    
    for x in params_l:

        if (x[0] == 'space_left_action' and x[1].lower() == 'email'):
            num_passes += 1

        if (x[0] == 'action_mail_acct' and x[1].lower() == 'root'):
            num_passes += 1

        if (x[0] == 'admin_space_left_action' and x[1].lower() == 'halt'):
            num_passes += 1
        
    if (num_passes == 3):

        pass_l.append('(4.1.1.2) System is configured to deal with space running out when auditd logs full')

    else:

        fail_l.append('(4.1.1.2) System needs to be configured to deal with space running out when auditd logs full')

        msg = ' Set the following parameters in /etc/audit/auditd.conf:'
        msg = color_symbol_debug() + text_color_yellow("%s\n\n" % msg)
        msg += "\t  " + text_color_green('space_left_action = email\n')
        msg += "\t  " + text_color_green('action_mail_acct = root\n')
        msg += "\t  " + text_color_green('admin_space_left_action = halt\n')

        remediation_msg_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #         4.1.1.3 Ensure audit logs are not automatically deleted         #
    ###########################################################################

    cmd1 = "grep max_log_file_action /etc/audit/auditd.conf"

    stdout1, stderr1, rc1 = run_cmd(cmd1)

    test_failed = False
    
    if (rc1 == 0):

        l = stdout1.splitlines()
        l = remove_all_elements_from_list(l, starts_with_l=['#'])

        if (len(l) != 0):

            l = l[0].split('=')

            if (l[0].strip() == 'max_log_file_action' and l[1].strip().lower() == 'keep_logs'):
                pass_l.append('(4.1.1.3) Audit logs are not being automatically deleted')
            else:
                test_failed = True
        else:
            test_failed = True

    else:
        test_failed = True

    if (test_failed):
        fail_l.append("(4.1.1.3) Audit logs need to be configured so that it doesn't get automatically deleted")

        msg = ' Set the following parameter in /etc/audit/auditd.conf:'
        msg = color_symbol_debug() + text_color_yellow("%s\n\n" % msg)
        msg += "\t  " + text_color_green('max_log_file_action = keep_logs\n')

        remediation_msg_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #                   4.1.2 Ensure auditd is installed                      #
    ###########################################################################

    output1 = pkgmgr_search_if_installed('audit')
    output2 = pkgmgr_search_if_installed('audit-libs')

    if (output1 or output2):
        pass_l.append('(4.1.2) Auditd is installed')
    else:
        fail_l.append('(4.1.2) Auditd needs to be installed')

        msg = ' Install Auditd:'
        msg = color_symbol_debug() + text_color_yellow("%s\n\n" % msg)
        msg += "\t  " + text_color_orange('%s\n' % pkgmgr_print_install_cmd('audit audit-libs'))

        remediation_msg_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #                 4.1.3 Ensure auditd service is enabled                  #
    ###########################################################################

    cmd1 = "systemctl is-enabled auditd"

    stdout1, stderr1, rc1 = run_cmd(cmd1)

    test_failed = False
    
    if (rc1 != 0):

        fail_l.append('(4.1.3) Auditd service needs to be enabled')

        msg = ' Enable Auditd service'
        msg = color_symbol_debug() + text_color_yellow("%s\n\n" % msg)
        msg += "\t  " + text_color_orange('sudo systemctl enable --now auditd.service\n')
        msg += "\t  " + text_color_orange('sudo update-rc.d auditd enable\n')

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(4.1.3) Auditd service is enabled')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    #############################################################################
    # 4.1.4 Ensure auditing for processes that start prior to auditd is enabled #
    #############################################################################

    cmd1 = 'grep "\S*linux*" /boot/grub/grub.cfg | grep "audit=1"'
    cmd2 = 'grep "\S*linux*" /boot/grub2/grub.cfg | grep "audit=1"'

    stdout1, stderr1, rc1 = run_cmd(cmd1)
    stdout2, stderr2, rc2 = run_cmd(cmd2)

    if (rc1 == 0 or rc2 == 0):

        pass_l.append('(4.1.4) Auditd is enabled in boot settings')

    else:

        fail_l.append('(4.1.4) Auditd needs to be enabled in boot settings')

        msg = ' Edit /etc/default/grub file & update the following information:'
        msg = color_symbol_debug() + text_color_yellow("%s\n\n" % msg)
        msg += "\t  " + text_color_green('GRUB_CMDLINE_LINUX="audit=1"\n')

        remediation_msg_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    #############################################################################
    #  4.1.5 Ensure events that modify date and time information are collected  #
    #############################################################################

    cmd1 = 'uname -m'

    stdout1, stderr1, rc1 = run_cmd(cmd1)

    sys_arch_32 = False

    if (rc1 == 0):
        if (stdout1.strip() != 'x86_64'):
            sys_arch_32 = True

        
    cmd1 = 'grep time-change /etc/audit/rules.d/*.rules | cut -d":" -f2'

    stdout1, stderr1, rc1 = run_cmd(cmd1)

    test_failed = False

    #TODO Code update to make sure the config passed if the parameter if not in the same sequence
    
    # config_32 = [['-a always,exit', '-F arch=b32', '-S adjtimex', '-S settimeofday', '-S stime', '-k time-change'], \
    #             ['-a always,exit', '-F arch=b32', '-S clock_settime', '-k time-change'], \
    #             ['-w /etc/localtime', '-p wa', '-k time-change']]

    # config_64 = [['-a always,exit', '-F arch=b64', '-S adjtimex', '-S settimeofday','-k time-change'], \
    #         ['-a always,exit', '-F arch=b32', '-S adjtimex', '-S settimeofday', '-S stime', '-k time-change'], \
    #         ['-a always,exit', '-F arch=b64', '-S clock_settime', '-k time-change'], \
    #         ['-a always,exit', '-F arch=b32', '-S clock_settime', '-k time-change',], \
    #         ['-w /etc/localtime', '-p wa', '-k time-change']]

    config_32 = [ '-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change', \
            '-a always,exit -F arch=b32 -S clock_settime -k time-change', \
            '-w /etc/localtime -p wa -k time-change' ]

    config_64 = [ '-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change', \
            '-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change', \
            '-a always,exit -F arch=b64 -S clock_settime -k time-change', \
            '-a always,exit -F arch=b32 -S clock_settime -k time-change', \
            '-w /etc/localtime -p wa -k time-change' ]

    if (rc1 == 0):

        l = remove_all_elements_from_list(stdout1.splitlines(), ['', '\n'], starts_with_l=['#' ])

        # print(l)
        # sys.exit(1)

        if (sys_arch_32):

            for c in config_32:

                try:
                    if (l.index(c) >= 0):
                        pass
                except (ValueError):
                    test_failed = True
                    break
        else:

            for c in config_64:

                try:
                    if (l.index(c) >= 0):
                        pass
                except (ValueError):
                    test_failed = True
                    break

    else:

        test_failed = True

    if (test_failed):

        msg = '(4.1.5) Auditd needs to be configured so that modification of day / time information is recorded'

        fail_l.append(msg)

        msg = ' Edit /etc/audit/rules.d/audit.rules with the following information:'

        if (sys_arch_32):

            msg = color_symbol_debug() + text_color_yellow("%s\n\n" % msg)
            msg += "\t  " + text_color_green('-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change\n')
            msg += "\t  " + text_color_green('-a always,exit -F arch=b32 -S clock_settime -k time-change\n ')
            msg += "\t  " + text_color_green('-w /etc/localtime -p wa -k time-change\n')

        else:

            msg = color_symbol_debug() + text_color_yellow("%s\n\n" % msg)

            msg += "\t " + text_color_green('-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change\n')
            msg += "\t " + text_color_green('-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change\n')
            msg += "\t " + text_color_green('-a always,exit -F arch=b64 -S clock_settime -k time-change\n')
            msg += "\t " + text_color_green('-a always,exit -F arch=b32 -S clock_settime -k time-change\n')
            msg += "\t " + text_color_green('-w /etc/localtime -p wa -k time-change\n')

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(4.1.5) Auditd is configured to record day / time change information')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #   4.1.6 Ensure events that modify user/group information are collected  #
    ###########################################################################

    cmd1 = "grep 'identity' /etc/audit/rules.d/*.rules | cut -d':' -f2"

    stdout1, stderr1, rc1 = run_cmd(cmd1)

    test_failed = False
    
    config = [ '-w /etc/group -p wa -k identity', '-w /etc/passwd -p wa -k identity', \
            '-w /etc/gshadow -p wa -k identity', '-w /etc/shadow -p wa -k identity',  \
            '-w /etc/security/opasswd -p wa -k identity' ]

    if (rc1 == 0):

        l = remove_all_elements_from_list(stdout1.splitlines(), ['', '\n'], starts_with_l=['#' ])

        # print(l)
        # sys.exit(1)

        found = False

        for c in config:

            try:
                if (l.index(c) >= 0):
                    pass
            except (ValueError):
                test_failed = True
                break
    else:

        test_failed = True

    if (test_failed):

        msg = '(4.1.6) Auditd needs to be configured so that modification of user / group information is recorded'

        fail_l.append(msg)

        msg = ' Configure Auditd to record modification of user/group information by adding the following lines to /etc/audit/rules.d/audit.rules:'

        msg = color_symbol_debug() + text_color_yellow("%s\n\n" % msg)
        msg += "\t  " + text_color_green('-w /etc/group -p wa -k identity\n')
        msg += "\t  " + text_color_green('-w /etc/passwd -p wa -k identity\n ')
        msg += "\t  " + text_color_green('-w /etc/gshadow -p wa -k identity\n')
        msg += "\t  " + text_color_green('-w /etc/shadow -p wa -k identity\n')
        msg += "\t  " + text_color_green('-w /etc/security/opasswd -p wa -k identity\n')

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(4.1.6) Auditd is configured to record modification of user / group information')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ##################################################################################
    # 4.1.7 Ensure events that modify the system's network environment are collected #
    ##################################################################################

    # Remove this block of code as it's being called once already, keeping this for testing
    cmd1 = 'uname -m'

    stdout1, stderr1, rc1 = run_cmd(cmd1)

    sys_arch_32 = False

    if (rc1 == 0):
        if (stdout1.strip() != 'x86_64'):
            sys_arch_32 = True

    #######################################################################################

    cmd1 = "grep 'system-locale' /etc/audit/rules.d/*.rules | cut -d':' -f2"

    stdout1, stderr1, rc1 = run_cmd(cmd1)

    test_failed = False
    
    config_32 = [ '-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale', \
            '-w /etc/issue -p wa -k system-locale', '-w /etc/issue.net -p wa -k system-locale', \
            '-w /etc/hosts -p wa -k system-locale', '-w /etc/sysconfig/network -p wa -k system-locale']

    config_64 = [ '-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale', \
            '-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale', \
            '-w /etc/issue -p wa -k system-locale', '-w /etc/issue.net -p wa -k system-locale', \
            '-w /etc/hosts -p wa -k system-locale', '-w /etc/sysconfig/network -p wa -k system-locale']

    if (rc1 == 0):

        l = remove_all_elements_from_list(stdout1.splitlines(), ['', '\n'], starts_with_l=['#' ])

        # print(l)
        # sys.exit(1)

        if (sys_arch_32):

            for c in config_32:

                try:
                    if (l.index(c) >= 0):
                        pass
                except (ValueError):
                    test_failed = True
                    break
        else:

            for c in config_64:

                try:
                    if (l.index(c) >= 0):
                        pass
                except (ValueError):
                    test_failed = True
                    break

    else:

        test_failed = True

    if (test_failed):

        msg = '(4.1.7) Auditd needs to be configured so that modification of systems network information is recorded'

        fail_l.append(msg)

        msg = ' Configure Auditd to record modification of system network information by editing /etc/audit/rules.d/audit.rules:'

        if (sys_arch_32):

            msg = color_symbol_debug() + text_color_yellow("%s\n\n" % msg)
            msg += "\t  " + text_color_green('-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change\n')
            msg += "\t  " + text_color_green('-a always,exit -F arch=b32 -S clock_settime -k time-change\n ')
            msg += "\t  " + text_color_green('-w /etc/localtime -p wa -k time-change\n')

        else:

            msg = color_symbol_debug() + text_color_yellow("%s\n\n" % msg)

            msg += "\t " + text_color_green('-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change\n')
            msg += "\t " + text_color_green('-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change\n')
            msg += "\t " + text_color_green('-a always,exit -F arch=b64 -S clock_settime -k time-change\n')
            msg += "\t " + text_color_green('-a always,exit -F arch=b32 -S clock_settime -k time-change\n')
            msg += "\t " + text_color_green('-w /etc/localtime -p wa -k time-change\n')

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(4.1.7) Auditd is configured to record modification of systems network information')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    # 4.1.8 Ensure events that modify the system's Mandatory Access Controls are collected #
    ########################################################################################

    cmd1 = "grep MAC-policy /etc/audit/rules.d/*.rules"

    stdout1, stderr1, rc1 = run_cmd(cmd1)

    pass_selinux = True
    pass_apparmor = True
    test_failed = False
    
    config_selinux = ['-w /etc/selinux/ -p wa -k MAC-policy', '-w /usr/share/selinux/ -p wa -k MAC-policy']
    config_apparmor = ['-w /etc/apparmor/ -p wa -k MAC-policy', '-w /etc/apparmor.d/ -p wa -k MAC-policy']

    if (rc1 == 0):

        l = remove_all_elements_from_list(stdout1.splitlines(), ['', '\n'], starts_with_l=['#' ])

        # print(l)
        # sys.exit(1)

        
        for c in config_selinux:

            try:
                if (l.index(c) >= 0):
                    pass
            except (ValueError):
                pass_selinux = False
                break
        
        for c in config_apparmor:

            try:
                if (l.index(c) >= 0):
                    pass
            except (ValueError):
                pass_apparmor = False
                break

        if (not (pass_selinux or pass_apparmor)):
            test_failed = True

    else:
        test_failed = True

    if (test_failed):

        msg = '(4.1.8) Events that modify MAC (Mandatory Access Control Lists) need to be recorded'

        fail_l.append(msg)

        msg = ' MAC events need to be recorded '
        msg = color_symbol_debug() + text_color_yellow("%s\n\n" % msg)
        msg += text_color_yellow('\tOn systems using SELinux add the following information to the file: /etc/audit/rules.d/audit.rules\n\n')
        msg += "\t  " + text_color_green('-w /etc/selinux/ -p wa -k MAC-policy\n')
        msg += "\t  " + text_color_green('-w /usr/share/selinux/ -p wa -k MAC-policy\n\n')

        msg += text_color_yellow('\tOn systems using Apparmor add the following information to the file: /etc/audit/rules.d/audit.rules\n\n')
        msg += "\t " + text_color_green('-w /etc/apparmor/ -p wa -k MAC-policy\n')
        msg += "\t " + text_color_green('-w /etc/apparmor.d/ -p wa -k MAC-policy\n')

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(4.1.8) Events modifying MAC information are being recorded by auditctl')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #               4.1.10 Ensure session initiation information is collected              #
    ########################################################################################

    cmd1 = "grep -E '(session|logins)' /etc/audit/rules.d/*.rules"

    stdout1, stderr1, rc1 = run_cmd(cmd1)

    test_failed = False
    
    config = ['-w /var/run/utmp -p wa -k session', '-w /var/log/wtmp -p wa -k logins', '-w /var/log/btmp -p wa -k logins']

    if (rc1 == 0):

        l = remove_all_elements_from_list(stdout1.splitlines(), ['', '\n'], starts_with_l=['#' ])

        # print(l)
        # sys.exit(1)
        
        for c in config:

            try:
                if (l.index(c) >= 0):
                    pass
            except (ValueError):
                test_failed = False
                break
    else:
        test_failed = True

    if (test_failed):

        msg = '(4.1.10) Session initiation information need to be recorded'

        fail_l.append(msg)

        msg = ' Record session initiation events by adding the following information to /etc/audit/rules.d/audit.rules'
        msg = color_symbol_debug() + text_color_yellow("%s\n\n" % msg)
        msg += "\t  " + text_color_green('-w /var/run/utmp -p wa -k session\n')
        msg += "\t  " + text_color_green('-w /var/log/wtmp -p wa -k logins\n')
        msg += "\t  " + text_color_green('-w /var/log/btmp -p wa -k logins\n')

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(4.1.10) Session initiation information is being recorded')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################################
    # 4.1.11 Ensure discretionary access control permission modification events are collected #
    ###########################################################################################

    # Remove this block of code as it's being called once already, keeping this for testing
    cmd1 = 'uname -m'

    stdout1, stderr1, rc1 = run_cmd(cmd1)

    sys_arch_32 = False

    if (rc1 == 0):
        if (stdout1.strip() != 'x86_64'):
            sys_arch_32 = True

    #######################################################################################

    cmd1 = "grep perm_mod /etc/audit/rules.d/*.rules"

    stdout1, stderr1, rc1 = run_cmd(cmd1)

    test_failed = False
    
    config_32 = ['-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=-1 -k perm_mod', \
            '-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=-1 -k perm_mod', \
            '-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=-1 -k perm_mod']

    config_64 = ['-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=-1 -k perm_mod', \
            '-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=-1 -k perm_mod', \
            '-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=-1 -k perm_mod', \
            '-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=-1 -k perm_mod', \
            '-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=-1 -k perm_mod', \
            '-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=-1 -k perm_mod']

    if (rc1 == 0):

        l = remove_all_elements_from_list(stdout1.splitlines(), ['', '\n'], starts_with_l=['#' ])

        # print(l)
        # sys.exit(1)

        if (sys_arch_32):

            for c in config_32:

                try:
                    if (l.index(c) >= 0):
                        pass
                except (ValueError):
                    test_failed = True
                    break
        else:

            for c in config_64:

                try:
                    if (l.index(c) >= 0):
                        pass
                except (ValueError):
                    test_failed = True
                    break

    else:

        test_failed = True

    if (test_failed):

        msg = '(4.1.11) Discretionary Access Control permission modification events need to be recorded'

        fail_l.append(msg)

        msg = ' Configure Auditd to record DAC permission modification information by editing /etc/audit/rules.d/audit.rules:'

        if (sys_arch_32):

            msg = color_symbol_debug() + text_color_yellow("%s\n\n" % msg)
            msg += "\t  " + text_color_green('-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=-1 -k perm_mod')
            msg += "\t  " + text_color_green('-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=-1 -k perm_mod\n ')
            txt = '-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=-1 -k perm_mod'
            txt += '-S fremovexattr -F auid>=500 -F auid!=-1 -k perm_mod'
            msg += "\t  " + text_color_green('%s\n' % txt)

        else:

            msg = color_symbol_debug() + text_color_yellow("%s\n\n" % msg)

            msg += "\t " + text_color_green('-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=-1 -k perm_mod\n')
            msg += "\t " + text_color_green('-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=-1 -k perm_mod\n')
            msg += "\t " + text_color_green('-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=-1 -k perm_mod\n')
            msg += "\t " + text_color_green('-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=-1 -k perm_mod\n')
            msg += "\t " + text_color_green('-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=-1 -k perm_mod\n')
            msg += "\t " + text_color_green('-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=-1 -k perm_mod\n')

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(4.1.11) Auditd is configured to record DAC permission modification information\n')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################################
    #       4.1.12 Ensure unsuccessful unauthorized file access attempts are collected        #
    ###########################################################################################

    # Remove this block of code as it's being called once already, keeping this for testing
    cmd1 = 'uname -m'

    stdout1, stderr1, rc1 = run_cmd(cmd1)

    sys_arch_32 = False

    if (rc1 == 0):
        if (stdout1.strip() != 'x86_64'):
            sys_arch_32 = True

    #######################################################################################

    cmd1 = "grep access /etc/audit/rules.d/*.rules"

    stdout1, stderr1, rc1 = run_cmd(cmd1)

    test_failed = False
    
    config_32 = ['-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=-1 -k access', \
            '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=-1 -k access']

    config_64 = ['-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access', \
            '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access', \
            '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access', \
            '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access']

    if (rc1 == 0):

        l = remove_whitespace_from_list(remove_all_elements_from_list(stdout1.splitlines(), ['', '\n'], starts_with_l=['#' ]))

        # print(l)
        # sys.exit(1)

        if (sys_arch_32):

            for c in config_32:

                try:
                    if (l.index(c) >= 0):
                        pass
                except (ValueError):
                    test_failed = True
                    break
        else:

            for c in config_64:

                try:
                    if (l.index(c) >= 0):
                        pass
                except (ValueError):
                    test_failed = True
                    break

    else:

        test_failed = True

    if (test_failed):

        msg = '(4.1.12) Unsuccessful / unauthorized file access events need to be recorded'

        fail_l.append(msg)

        msg = ' Configure Auditd to record unsuccessful / unauthorized file access events by editing /etc/audit/rules.d/audit.rules:'

        if (sys_arch_32):

            msg = color_symbol_debug() + text_color_yellow("%s\n\n" % msg)
            msg += "\t  " + text_color_green('%s\n' % txt)
            msg += "\t " + text_color_green('-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=-1 -k access\n')
            msg += "\t " + text_color_green('-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=-1 -k access\n')

        else:

            msg = color_symbol_debug() + text_color_yellow("%s\n\n" % msg)
            msg += "\t " + text_color_green('-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access\n')
            msg += "\t " + text_color_green('-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access\n')
            msg += "\t " + text_color_green('-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access\n')
            msg += "\t " + text_color_green('-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access\n')

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(4.1.12) Auditd is configured to record unauthorized / unsuccessful file access information\n')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #               4.1.13 Ensure use of privileged commands is collected                  #
    ########################################################################################

    cmd1 = 'find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk \'{print "-a always,exit -F path=" $1 " -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged" }\''

    stdout1, stderr1, rc1 = run_cmd(cmd1)

    test_failed = False
    
    l = []

    if (rc1 == 0):

        l = remove_all_elements_from_list(stdout1.splitlines(), ['', '\n'])

        if (len(l) != 0):
            test_failed = True

    else:
        test_failed = True

    if (test_failed):

        msg = '(4.1.13) Use of privileged commands needs to be recorded'

        fail_l.append(msg)

        msg = ' To record use of privileged commands add the following information to /etc/audit/rules.d/audit.rules'
        msg = color_symbol_debug() + text_color_yellow("%s\n\n" % msg)

        for line in l:
            msg += "\t  " + text_color_green('%s\n' % line)

        remediation_msg_l.append(msg)

    else:
        pass_l.append('(4.1.13) Use of privileged commands is being recorded')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #               4.1.14 Ensure successful file system mounts are collected              #
    ########################################################################################

    # Remove this block of code as it's being called once already, keeping this for testing
    cmd1 = 'uname -m'

    stdout1, stderr1, rc1 = run_cmd(cmd1)

    sys_arch_32 = False

    if (rc1 == 0):
        if (stdout1.strip() != 'x86_64'):
            sys_arch_32 = True

    #######################################################################################

    cmd1 = 'grep mounts /etc/audit/rules.d/*.rules'

    stdout1, stderr1, rc1 = run_cmd(cmd1)

    test_failed = False
    
    config_32 = ['-a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k mounts']

    config_64 = ['-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k mounts', \
            '-a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k mounts']

    if (rc1 == 0):

        l = remove_all_elements_from_list(stdout1.splitlines(), ['', '\n'], starts_with_l=['#' ])

        if (sys_arch_32):

            for c in config_32:

                try:
                    if (l.index(c) >= 0):
                        pass
                except (ValueError):
                    test_failed = True
                    break
        else:

            for c in config_64:

                try:
                    if (l.index(c) >= 0):
                        pass
                except (ValueError):
                    test_failed = True
                    break
    else:

        test_failed = True

    if (test_failed):

        msg = '(4.1.14) Auditd needs to be configured so that information pertaining to successful filesystem mounts get recorded'

        fail_l.append(msg)

        msg = ' Configure Auditd to record information about successful filesystem mounts by editing /etc/audit/rules.d/audit.rules:'

        if (sys_arch_32):

            msg = color_symbol_debug() + text_color_yellow("%s\n\n" % msg)
            msg += "\t  " + text_color_green('-a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k mounts\n')

        else:

            msg = color_symbol_debug() + text_color_yellow("%s\n\n" % msg)

            msg += "\t " + text_color_green('-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k mounts\n')
            msg += "\t " + text_color_green('-a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k mounts\n')

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(4.1.14) Auditd is configured to record information pertaining to successful filesystem mounts')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #               4.1.15 Ensure file deletion events by users are collected              #
    ########################################################################################

    # Remove this block of code as it's being called once already, keeping this for testing
    cmd1 = 'uname -m'

    stdout1, stderr1, rc1 = run_cmd(cmd1)

    sys_arch_32 = False

    if (rc1 == 0):
        if (stdout1.strip() != 'x86_64'):
            sys_arch_32 = True

    #######################################################################################

    cmd1 = 'grep delete /etc/audit/rules.d/*.rules'

    stdout1, stderr1, rc1 = run_cmd(cmd1)

    test_failed = False
    
    config_32 = ['-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete']

    config_64 = ['-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete', \
            '-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete']

    if (rc1 == 0):

        l = remove_all_elements_from_list(stdout1.splitlines(), ['', '\n'], starts_with_l=['#' ])

        if (sys_arch_32):

            for c in config_32:

                try:
                    if (l.index(c) >= 0):
                        pass
                except (ValueError):
                    test_failed = True
                    break
        else:

            for c in config_64:

                try:
                    if (l.index(c) >= 0):
                        pass
                except (ValueError):
                    test_failed = True
                    break
    else:

        test_failed = True

    if (test_failed):

        msg = '(4.1.15) Auditd needs to be configured so that file deletion events get recorded'

        fail_l.append(msg)

        msg = ' Configure Auditd to record file deletion events by editing /etc/audit/rules.d/audit.rules:'

        if (sys_arch_32):

            msg = color_symbol_debug() + text_color_yellow("%s\n\n" % msg)
            msg += "\t  " + text_color_green('-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete\n')

        else:

            msg = color_symbol_debug() + text_color_yellow("%s\n\n" % msg)

            msg += "\t " + text_color_green('-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete\n')
            msg += "\t " + text_color_green('-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete\n')

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(4.1.15) Auditd is configured to record information about file deletion events')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #     4.1.16 Ensure changes to system administration scope (sudoers) is collected      #
    ########################################################################################

    cmd1 = "grep scope /etc/audit/rules.d/*.rules"

    stdout1, stderr1, rc1 = run_cmd(cmd1)

    test_failed = False
    
    config = ['-w /etc/sudoers -p wa -k scope', '-w /etc/sudoers.d/ -p wa -k scope']

    if (rc1 == 0):

        l = remove_all_elements_from_list(stdout1.splitlines(), ['', '\n'], starts_with_l=['#' ])

        for c in config:

            try:
                if (l.index(c) >= 0):
                    pass
            except (ValueError):
                test_failed = False
                break
    else:
        test_failed = True

    if (test_failed):

        msg = '(4.1.16) Changes to system administration scope needs to be recorded'

        fail_l.append(msg)

        msg = ' Record session initiation events by adding the following information to /etc/audit/rules.d/audit.rules'
        msg = color_symbol_debug() + text_color_yellow("%s\n\n" % msg)
        msg += "\t  " + text_color_green('-w /etc/sudoers -p wa -k scope\n')
        msg += "\t  " + text_color_green('-w /etc/sudoers.d/ -p wa -k scope\n')

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(4.1.16) Changes to system administration scope is being recorded')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #          4.1.17 Ensure system administrator actions (sudolog) are collected          #
    ########################################################################################

    cmd1 = "grep actions /etc/audit/rules.d/*.rules"

    stdout1, stderr1, rc1 = run_cmd(cmd1)

    test_failed = False
    
    config = ['-w /var/log/sudo.log -p wa -k actions']

    if (rc1 == 0):

        l = remove_all_elements_from_list(stdout1.splitlines(), ['', '\n'], starts_with_l=['#' ])

        for c in config:

            try:
                if (l.index(c) >= 0):
                    pass
            except (ValueError):
                test_failed = False
                break
    else:
        test_failed = True

    if (test_failed):

        msg = '(4.1.17) System administrator actions needs to be recorded'

        fail_l.append(msg)

        msg = ' Record system administrator actions by adding the following information to /etc/audit/rules.d/audit.rules'
        msg = color_symbol_debug() + text_color_yellow("%s\n\n" % msg)
        msg += "\t  " + text_color_green('-w /var/log/sudo.log -p wa -k actions\n')

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(4.1.17) Actions taken by system administrator is being recorded')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #            4.1.18 Ensure kernel module loading and unloading is collected            #
    ########################################################################################

    # Remove this block of code as it's being called once already, keeping this for testing
    cmd1 = 'uname -m'

    stdout1, stderr1, rc1 = run_cmd(cmd1)

    sys_arch_32 = False

    if (rc1 == 0):
        if (stdout1.strip() != 'x86_64'):
            sys_arch_32 = True

    #######################################################################################

    cmd1 = 'grep modules /etc/audit/rules.d/*.rules'

    stdout1, stderr1, rc1 = run_cmd(cmd1)

    test_failed = False
    
    config_32 = ['-w /sbin/insmod -p x -k modules', '-w /sbin/rmmod -p x -k modules', \
            '-w /sbin/modprobe -p x -k modules', '-a always,exit -F arch=b32 -S init_module -S delete_module -k modules']

    config_64 = ['-w /sbin/insmod -p x -k modules', '-w /sbin/rmmod -p x -k modules', \
            '-w /sbin/modprobe -p x -k modules', '-a always,exit -F arch=b64 -S init_module -S delete_module -k modules']

    if (rc1 == 0):

        l = remove_all_elements_from_list(stdout1.splitlines(), ['', '\n'], starts_with_l=['#' ])

        if (sys_arch_32):

            for c in config_32:

                try:
                    if (l.index(c) >= 0):
                        pass
                except (ValueError):
                    test_failed = True
                    break
        else:

            for c in config_64:

                try:
                    if (l.index(c) >= 0):
                        pass
                except (ValueError):
                    test_failed = True
                    break
    else:

        test_failed = True

    if (test_failed):

        msg = '(4.1.18) Auditd needs to be configured so that kernel module loading / unloading activity is being recorded'

        fail_l.append(msg)

        msg = ' Configure Auditd to record kernel module loading / unloading events by editing /etc/audit/rules.d/audit.rules:'

        if (sys_arch_32):

            msg = color_symbol_debug() + text_color_yellow("%s\n\n" % msg)
            msg += "\t  " + text_color_green('-w /sbin/insmod -p x -k modules\n')
            msg += "\t  " + text_color_green('-w /sbin/rmmod -p x -k modules\n')
            msg += "\t  " + text_color_green('-w /sbin/modprobe -p x -k modules\n')
            msg += "\t  " + text_color_green('-a always,exit -F arch=b32 -S init_module -S delete_module -k modules\n')

        else:

            msg = color_symbol_debug() + text_color_yellow("%s\n\n" % msg)

            msg += "\t " + text_color_green('-w /sbin/insmod -p x -k modules\n')
            msg += "\t " + text_color_green('-w /sbin/rmmod -p x -k modules\n')
            msg += "\t " + text_color_green('-w /sbin/modprobe -p x -k modules\n')
            msg += "\t " + text_color_green('-a always,exit -F arch=b64 -S init_module -S delete_module -k modules\n')

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(4.1.18) Auditd is configured to record kernel module loading / unloading information')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #               4.1.19 Ensure the audit configuration is immutable                     #
    ########################################################################################

    cmd1 = 'grep "^\s*[^#]" /etc/audit/rules.d/*.rules | tail -1'

    stdout1, stderr1, rc1 = run_cmd(cmd1)

    test_failed = True
    
    if (rc1 == 0):

        l = remove_all_elements_from_list(stdout1.splitlines(), ['', '\n'], starts_with_l=['#' ])

        config = ['-e 2']

        for c in config:

            try:
                if (l.index(c) >= 0):
                    test_failed = False
                    break
            except (ValueError):
                pass
    else:

        test_failed = True

    if (test_failed):

        msg = '(4.1.19) Audit configurations need to be immutable'

        fail_l.append(msg)

        msg = ' Audit configurations need to be immutable, add the following to /etc/audit/rules.d/audit.rules'
        msg = color_symbol_debug() + text_color_yellow("%s\n\n" % msg)
        msg += "\t  " + text_color_green('-e 2\n')

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(4.1.19) Audit configurations are immutable')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #                       4.2.1.1 Ensure rsyslog is installed                            #
    ########################################################################################

    pkg_found = pkgmgr_search_if_installed('rsyslog')

    if (pkg_found):

        pass_l.append('(4.2.1.1) Rsyslog package is installed')

    else:

        msg = '(4.2.1.1) Rsyslog package needs to be installed'

        fail_l.append(msg)

        msg = ' Install rsyslog package:'
        msg = color_symbol_debug() + text_color_yellow("%s\n\n" % msg)
        msg += "\t  " + text_color_orange('%s\n' % pkgmgr_print_install_cmd('rsyslog'))

        remediation_msg_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #                     4.2.1.2 Ensure rsyslog service is enabled                        #
    ########################################################################################

    cmd1 = 'systemctl is-enabled rsyslog'

    stdout1, stderr1, rc1 = run_cmd(cmd1)

    if (rc1 == 0):

        pass_l.append('(4.2.1.2) Rsyslog service has been enabled')

    else:

        msg = '(4.2.1.2) Rsyslog needs to be enabled'

        fail_l.append(msg)

        msg = ' Enable rsyslog service:'
        msg = color_symbol_debug() + text_color_yellow("%s\n\n" % msg)
        msg += "\t  " + text_color_orange('sudo systemctl enable rsyslog\n')
        msg += "\t  " + text_color_orange('sudo update-rc.d rsyslog enable\n')

        remediation_msg_l.append(msg)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #               4.2.1.4 Ensure rsyslog default file permissions configured             #
    ########################################################################################

    cmd1 = 'grep ^\$FileCreateMode /etc/rsyslog.conf /etc/rsyslog.d/*.conf | cut -d":" -f2'

    stdout1, stderr1, rc1 = run_cmd(cmd1)

    test_failed = True

    if (rc1 == 0):

        config = ['$FileCreateMode 0640']

        l = stdout1.splitlines()

        for item in l:

            if (item.strip() == config[0]):
                test_failed = False
            else:
                pass


    if (test_failed):

        msg = '(4.2.1.4) Default file permissions need to be configured for rsyslog'

        fail_l.append(msg)

        msg = ' Configure default permissions for rsyslog by adding the following in /etc/rsyslog.conf'
        msg = color_symbol_debug() + text_color_yellow("%s\n\n" % msg)
        msg += "\t  " + text_color_green('$FileCreateMode 0640\n')

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(4.2.1.4) Rsyslog is configured to handle default file permissions')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #         4.2.1.5 Ensure rsyslog is configured to send logs to a remote log host       #
    ########################################################################################

    cmd1 = 'grep "^*.*[^I][^I]*@" /etc/rsyslog.conf /etc/rsyslog.d/*.conf'

    stdout1, stderr1, rc1 = run_cmd(cmd1)

    test_failed = True

    if (rc1 == 0):

            test_failed = False

    if (test_failed):

        msg = '(4.2.1.5) Rsyslog needs to be configured such that it sends log files to remote host'

        fail_l.append(msg)

        msg = ' Configure rsyslog to send log files to remote host by adding the following to /etc/rsyslog.conf (replace host with logging host)'
        msg = color_symbol_debug() + text_color_yellow("%s\n\n" % msg)
        msg += "\t  " + text_color_green('*.* @@loghost.example.com\n')

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(4.2.1.5) Rsyslog is configured to send log files to remote host')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #             4.2.2.1 Ensure journald is configured to send logs to rsyslog            #
    ########################################################################################

    cmd1 = 'grep -e ForwardToSyslog /etc/systemd/journald.conf'

    stdout1, stderr1, rc1 = run_cmd(cmd1)

    test_failed = True

    if (rc1 == 0):

        l = remove_all_elements_from_list(stdout1.splitlines(), ['', '\n'], starts_with_l=['#' ])

        try:
            if (l.index('ForwardToSyslog=yes') >= 0):
                test_failed = False
        except ValueError:
            pass

    if (test_failed):

        msg = '(4.2.2.1) Journald is configured to send logs to rsyslog'

        fail_l.append(msg)

        msg = ' Configure journald to send log files to rsyslog by adding the following lines to /etc/systemd/journald.conf'
        msg = color_symbol_debug() + text_color_yellow("%s\n\n" % msg)
        msg += "\t  " + text_color_green('ForwardToSyslog=yes\n')

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(4.2.2.1) Journald is configured to send logs to rsyslog')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #           4.2.2.2 Ensure journald is configured to compress large log files          #
    ########################################################################################

    cmd1 = 'grep -e Compress /etc/systemd/journald.conf'

    stdout1, stderr1, rc1 = run_cmd(cmd1)

    test_failed = True

    if (rc1 == 0):

        l = remove_all_elements_from_list(stdout1.splitlines(), ['', '\n'], starts_with_l=['#' ])

        try:
            if (l.index('Compress=yes') >= 0):
                test_failed = False
        except ValueError:
            pass

    if (test_failed):

        msg = '(4.2.2.2) Journald is not configured to compress large log files'

        fail_l.append(msg)

        msg = ' Configure journald to compress log files by adding the following lines to /etc/systemd/journald.conf'
        msg = color_symbol_debug() + text_color_yellow("%s\n\n" % msg)
        msg += "\t  " + text_color_green('Compress=yes\n')

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(4.2.2.2) Journald is configured to compress large log files')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #               4.2.3 Ensure permissions on all logfiles are configured                #
    ########################################################################################

    output = search_for_file('/var/log', '*')

    test_failed = True

    fl = []

    if (output[0]):

        for f in output[1]:
            user_perm, group_perm, other_perm = get_file_permission(f)

            if (group_perm == 4 and other_perm != 0):
                fl.append(f)
                test_failed = True

    if (test_failed):

        msg = '(4.2.3) Secure permissions need to be set on all log files'

        fail_l.append(msg)

        msg = " Configure secure permissions for log files:"

        msg = color_symbol_debug() + text_color_yellow("%s\n\n" % msg)

        for f in fl:
            msg += "\t  " + text_color_orange('sudo chmod g-wx,o-rwx %s\n' % f)

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(4.2.3) Secure permissions are configured on all log files')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #                5.1.2 Ensure permissions on /etc/crontab are configured               #
    ########################################################################################

    fp = '/etc/crontab'

    test_failed = False

    perm_incorrect = False
    owner_incorrect = False

    if (not os.path.isfile(fp)):

        pass

    else:

        user_perm, group_perm, other_perm = get_file_permission(fp)

        if (user_perm == 6 and group_perm == 0 and other_perm == 0):
            pass
        else:
            test_failed = True
            perm_incorrect = True

        attrs = os.stat(fp)

        uid = attrs.st_uid
        gid = attrs.st_gid

        if (uid == 0 and gid == 0):
            pass
        else:
            test_failed = True
            owner_incorrect = True

        if (test_failed):

            msg = '(5.1.2) Secure permissions need to be set on %s file' % fp

            fail_l.append(msg)

            msg = " Configure secure permissions for %s:" % fp

            msg = color_symbol_debug() + text_color_yellow("%s\n\n" % msg)

            if (perm_incorrect):
                msg += "\t  " + text_color_orange('sudo chmod og-rwx %s\n' % fp)

            if (owner_incorrect):
                msg += "\t  " + text_color_orange('sudo chown root:root %s\n' % fp)

            remediation_msg_l.append(msg)

        else:

            pass_l.append('(5.1.2) Secure permissions are configured for /etc/crontab file')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #             5.1.3 Ensure permissions on /etc/cron.hourly are configured              #
    ########################################################################################

    fp = '/etc/cron.hourly'

    test_failed = False

    perm_incorrect = False
    owner_incorrect = False

    if (not os.path.isdir(fp)):

        pass

    else:

        user_perm, group_perm, other_perm = get_file_permission(fp)

        if (user_perm == 6 and group_perm == 0 and other_perm == 0):
            pass
        else:
            test_failed = True
            perm_incorrect = True

        attrs = os.stat(fp)

        uid = attrs.st_uid
        gid = attrs.st_gid

        if (uid == 0 and gid == 0):
            pass
        else:
            test_failed = True
            owner_incorrect = True

        if (test_failed):

            msg = '(5.1.3) Secure permissions need to be set on %s file' % fp

            fail_l.append(msg)

            msg = " Configure secure permissions for %s:" % fp

            msg = color_symbol_debug() + text_color_yellow("%s\n\n" % msg)

            if (perm_incorrect):
                msg += "\t  " + text_color_orange('sudo chmod og-rwx %s\n' % fp)

            if (owner_incorrect):
                msg += "\t  " + text_color_orange('sudo chown root:root %s\n' % fp)

            remediation_msg_l.append(msg)

        else:

            pass_l.append('(5.1.3) Secure permissions are configured for %s file' % fp)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #               5.1.4 Ensure permissions on /etc/cron.daily are configured             #
    ########################################################################################

    fp = '/etc/cron.daily'

    test_failed = False

    perm_incorrect = False
    owner_incorrect = False

    if (not os.path.isdir(fp)):

        pass

    else:
        
        user_perm, group_perm, other_perm = get_file_permission(fp)

        if (user_perm == 7 and group_perm == 0 and other_perm == 0):
            pass
        else:
            test_failed = True
            perm_incorrect = True

        attrs = os.stat(fp)

        uid = attrs.st_uid
        gid = attrs.st_gid

        if (uid == 0 and gid == 0):

            pass

        else:
            test_failed = True
            owner_incorrect = True

        if (test_failed):

            msg = '(5.1.4) Secure permissions need to be set on %s file' % fp

            fail_l.append(msg)

            msg = " Configure secure permissions for %s:" % fp

            msg = color_symbol_debug() + text_color_yellow("%s\n\n" % msg)

            if (perm_incorrect):
                msg += "\t  " + text_color_orange('sudo chmod og-rwx %s\n' % fp)

            if (owner_incorrect):
                msg += "\t  " + text_color_orange('sudo chown root:root %s\n' % fp)

            remediation_msg_l.append(msg)

        else:

            pass_l.append('(5.1.4) Secure permissions are configured for %s file' % fp)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #              5.1.5 Ensure permissions on /etc/cron.weekly are configured             #
    ########################################################################################

    fp = '/etc/cron.weekly'

    test_failed = False

    perm_incorrect = False
    owner_incorrect = False

    if (not os.path.isdir(fp)):

        pass

    else:
        
        user_perm, group_perm, other_perm = get_file_permission(fp)

        if (user_perm == 6 and group_perm == 0 and other_perm == 0):
            pass
        else:
            test_failed = True
            perm_incorrect = True

        attrs = os.stat(fp)

        uid = attrs.st_uid
        gid = attrs.st_gid

        if (uid == 0 and gid == 0):
            pass
        else:
            test_failed = True
            owner_incorrect = True

        if (test_failed):

            msg = '(5.1.5) Secure permissions need to be set on %s file' % fp

            fail_l.append(msg)

            msg = " Configure secure permissions for %s:" % fp

            msg = color_symbol_debug() + text_color_yellow("%s\n\n" % msg)

            if (perm_incorrect):
                msg += "\t  " + text_color_orange('sudo chmod og-rwx %s\n' % fp)

            if (owner_incorrect):
                msg += "\t  " + text_color_orange('sudo chown root:root %s\n' % fp)

            remediation_msg_l.append(msg)

        else:

            pass_l.append('(5.1.5) Secure permissions are configured for %s file' % fp)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #             5.1.6 Ensure permissions on /etc/cron.monthly are configured             #
    ########################################################################################

    fp = '/etc/cron.monthly'

    test_failed = False

    perm_incorrect = False
    owner_incorrect = False

    if (not os.path.isdir(fp)):

        pass

    else:
        
        user_perm, group_perm, other_perm = get_file_permission(fp)

        if (user_perm == 6 and group_perm == 0 and other_perm == 0):
            pass
        else:
            test_failed = True
            perm_incorrect = True

        attrs = os.stat(fp)

        uid = attrs.st_uid
        gid = attrs.st_gid

        if (uid == 0 and gid == 0):

            pass

        else:

            test_failed = True
            owner_incorrect = True

        if (test_failed):

            msg = '(5.1.6) Secure permissions need to be set on %s file' % fp

            fail_l.append(msg)

            msg = " Configure secure permissions for %s:" % fp

            msg = color_symbol_debug() + text_color_yellow("%s\n\n" % msg)

            if (perm_incorrect):
                msg += "\t  " + text_color_orange('sudo chmod og-rwx %s\n' % fp)

            if (owner_incorrect):
                msg += "\t  " + text_color_orange('sudo chown root:root %s\n' % fp)

            remediation_msg_l.append(msg)

        else:

            pass_l.append('(5.1.6) Secure permissions are configured for %s file' % fp)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #                5.1.7 Ensure permissions on /etc/cron.d are configured                #
    ########################################################################################

    fp = '/etc/cron.d'

    test_failed = False

    perm_incorrect = False
    owner_incorrect = False

    if (not os.path.isdir(fp)):

        pass

    else:
        
        user_perm, group_perm, other_perm = get_file_permission(fp)

        if (user_perm == 6 and group_perm == 0 and other_perm == 0):

            pass

        else:
            test_failed = True
            perm_incorrect = True

        attrs = os.stat(fp)

        uid = attrs.st_uid
        gid = attrs.st_gid

        if (uid == 0 and gid == 0):

            pass

        else:

            test_failed = True
            owner_incorrect = True

        if (test_failed):

            msg = '(5.1.7) Secure permissions need to be set on %s file' % fp

            fail_l.append(msg)

            msg = " Configure secure permissions for %s:" % fp

            msg = color_symbol_debug() + text_color_yellow("%s\n\n" % msg)

            if (perm_incorrect):
                msg += "\t  " + text_color_orange('sudo chmod og-rwx %s\n' % fp)

            if (owner_incorrect):
                msg += "\t  " + text_color_orange('sudo chown root:root %s\n' % fp)

            remediation_msg_l.append(msg)

        else:

            pass_l.append('(5.1.7) Secure permissions are configured for %s file' % fp)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #   5.1.8 Ensure permissions on etc/at or etc/cron are restricted to authorized users  #
    ########################################################################################

    fl = []

    _fl = ['/etc/at.allow', '/etc/at.deny', '/etc/cron.allow', '/etc/cron.deny']

    for item in _fl:

        if (os.path.isfile(item)):
            fl.append(item)

    test_failed = False

    perm_incorrect = False
    owner_incorrect = False

    failed_perm_l = []
    failed_owner_l = []

    for f in fl:    

        user_perm, group_perm, other_perm = get_file_permission(f)

        if (user_perm == 6 and group_perm == 0 and other_perm == 0):

            pass

        else:

            test_failed = True
            perm_incorrect = True
            failed_perm_l.append(f)

        attrs = os.stat(f)

        uid = attrs.st_uid
        gid = attrs.st_gid

        if (uid == 0 and gid == 0):

            pass

        else:

            test_failed = True
            owner_incorrect = True
            failed_owner_l.append(f)

    if (test_failed):

        msg = "(5.1.8) Secure permissions need to be set files '/etc/at.[allow|deny] and /etc/cron.[allow|deny]'"

        fail_l.append(msg)

        msg = " Configure secure permissions for files:"

        msg = color_symbol_debug() + text_color_yellow("%s\n\n" % msg)

        if (perm_incorrect):
            for fp in failed_perm_l:
                msg += "\t  " + text_color_orange('sudo chmod og-rwx %s\n' % fp)

            msg += '\n'

        if (owner_incorrect):
            for fp in failed_owner_l:
                msg += "\t  " + text_color_orange('sudo chown root:root %s\n' % fp)

            # msg += '\n'

        remediation_msg_l.append(msg)

    else:

        pass_l.append("(5.1.8) Secure permissions are configured for '/etc/at.[allow|deny] and /etc/cron.[allow|deny]'")

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #           5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured            #
    ########################################################################################

    fp = '/etc/ssh/sshd_config'

    test_failed = False

    perm_incorrect = False
    owner_incorrect = False

    if (not os.path.isfile(fp)):

        pass

    else:

        user_perm, group_perm, other_perm = get_file_permission(fp)

        if (user_perm == 6 and group_perm == 0 and other_perm == 0):

            pass

        else:

            test_failed = True
            perm_incorrect = True

        attrs = os.stat(fp)

        uid = attrs.st_uid
        gid = attrs.st_gid

        if (uid == 0 and gid == 0):

            pass

        else:

            test_failed = True
            owner_incorrect = True

        if (test_failed):

            msg = '(5.2.1) Secure permissions need to be set on %s file' % fp

            fail_l.append(msg)

            msg = " Configure secure permissions for %s:" % fp

            msg = color_symbol_debug() + text_color_yellow("%s\n\n" % msg)

            if (perm_incorrect):
                msg += "\t  " + text_color_orange('sudo chmod og-rwx %s\n' % fp)

            if (owner_incorrect):
                msg += "\t  " + text_color_orange('sudo chown root:root %s\n' % fp)

            remediation_msg_l.append(msg)

        else:

            pass_l.append('(5.2.1) Secure permissions are configured for %s file' % fp)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #         5.2.2 Ensure permissions on SSH private host key files are configured        #
    ########################################################################################

    cmd = "find /etc/ssh -xdev -type f -name 'ssh_host_*_key'"

    stdout, stderr, rc = run_cmd(cmd)

    fl = stdout.splitlines()

    if (rc == 0 and len(fl) != 0): # If nothing found we skip this check

        test_failed = False

        perm_incorrect = False
        owner_incorrect = False

        failed_perm_l = []
        failed_owner_l = []

        for f in fl:

            user_perm, group_perm, other_perm = get_file_permission(f)

            if (user_perm == 6 and group_perm == 0 and other_perm == 0):

                pass

            else:

                test_failed = True
                perm_incorrect = True
                failed_perm_l.append(f)

            attrs = os.stat(f)

            uid = attrs.st_uid
            gid = attrs.st_gid

            if (uid == 0 and gid == 0):

                pass

            else:

                test_failed = True
                owner_incorrect = True
                failed_owner_l.append(f)

        if (test_failed):

            msg = "(5.2.2) Secure permissions need to be configured for SSH private keys"

            fail_l.append(msg)

            msg = " Configure secure permissions for the following SSH private keys:"

            msg = color_symbol_debug() + text_color_yellow("%s\n\n" % msg)

            if (perm_incorrect):
                for fp in failed_perm_l:
                    msg += "\t  " + text_color_orange('sudo chmod og-rwx %s\n' % fp)

                msg += '\n'

            if (owner_incorrect):
                for fp in failed_owner_l:
                    msg += "\t  " + text_color_orange('sudo chown root:root %s\n' % fp)

                msg += '\n'

            remediation_msg_l.append(msg)

        else:

            pass_l.append("(5.2.2) Secure permissions are configured for SSH private keys")

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #         5.2.3 Ensure permissions on SSH public host key files are configured         #
    ########################################################################################

    cmd = "find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub'"

    stdout, stderr, rc = run_cmd(cmd)

    fl = stdout.splitlines()

    if (rc == 0 and len(fl) != 0): # If nothing found we skip this check

        test_failed = False

        perm_incorrect = False
        owner_incorrect = False

        failed_perm_l = []
        failed_owner_l = []

        for f in fl:

            user_perm, group_perm, other_perm = get_file_permission(f)

            if (user_perm == 6 and group_perm == 4 and other_perm == 4):

                pass

            else:

                test_failed = True
                perm_incorrect = True
                failed_perm_l.append(f)

            attrs = os.stat(f)

            uid = attrs.st_uid
            gid = attrs.st_gid

            if (uid == 0 and gid == 0):

                pass

            else:

                test_failed = True
                owner_incorrect = True
                failed_owner_l.append(f)

        if (test_failed):

            msg = "(5.2.3) Secure permissions need to be configured for SSH pulic keyfiles"

            fail_l.append(msg)

            msg = " Configure secure permissions for the following SSH public keyfiles:"

            msg = color_symbol_debug() + text_color_yellow("%s\n\n" % msg)

            if (perm_incorrect):
                for fp in failed_perm_l:
                    msg += "\t  " + text_color_orange('sudo chmod og-rwx %s\n' % fp)

                msg += '\n'

            if (owner_incorrect):
                for fp in failed_owner_l:
                    msg += "\t  " + text_color_orange('sudo chown root:root %s\n' % fp)

                msg += '\n'

            remediation_msg_l.append(msg)

        else:

            pass_l.append("(5.2.3) Secure permissions are configured for SSH public keyfiles")

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #                                   SSH Config Audits                                  #
    ########################################################################################

    ssh_config_remediation = color_symbol_debug() + text_color_yellow(' Edit /etc/ssh/sshd_config & add the following parameters:\n\n')
    ssh_config_remediation += text_color_cyan('\t  ## Make sure to replace <userlist> with names of users you want to permit separated by space\n\n')
    ssh_config_fails = False


    ########################################################################################
    #                       5.2.4 Ensure SSH Protocol is set to 2                          #
    ########################################################################################

    # TODO: make this check for whitespace when grepping
    cmd = "grep '^Protocol' /etc/ssh/sshd_config"

    stdout, stderr, rc = run_cmd(cmd)

    test_failed = False
    
    if (rc == 0):

        output = stdout.splitlines()[0].split()[1]
        
        if (output != ''):

            n = convert_str_to_int(output)

            if (n[0] and n[1][0] == 2):
                pass
            else:
                test_failed = True
        else:
            test_failed = True
    else:
        test_failed = True

    if (test_failed):

        fail_l.append('(5.2.4) SSH config: Protocol version needs to be set to 2')

        msg = "\t  " + text_color_green('Protocol 2\n')

        ssh_config_remediation += msg

        ssh_config_fails = True

    else:

        pass_l.append('(5.2.4) SSH config: Protocol version is set to 2')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #                       5.2.5 Ensure SSH LogLevel is appropriate                       #
    ########################################################################################
  
    cmd = "grep '^LogLevel' /etc/ssh/sshd_config"

    stdout, stderr, rc = run_cmd(cmd)

    test_failed = False
    
    stdout = remove_all_elements_from_list(stdout.splitlines(), ['','\n'], starts_with_l=['#'])

    if (rc == 0 and len(stdout) != 0):

        output = stdout[0].split()[1].lower().strip()

        if (output != '' and (output == 'info' or output == 'verbose')):

            pass

        else:

            test_failed = True
    else:

        test_failed = True

    if (test_failed):

        fail_l.append('(5.2.5) SSH config: LogLevel needs to be set to verbose')

        msg = "\t  " + text_color_green('LogLevel VERBOSE\n')

        ssh_config_remediation += msg

        ssh_config_fails = True

    else:

        pass_l.append('(5.2.5) SSH config: Loglevel is set to verbose')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #                       5.2.6 Ensure SSH X11 forwarding is disabled                    #
    ########################################################################################

    cmd = "grep 'X11Forwarding' /etc/ssh/sshd_config"

    stdout, stderr, rc = run_cmd(cmd)

    test_failed = False

    stdout = remove_all_elements_from_list(stdout.splitlines(), ['','\n'], starts_with_l=['#'])

    if (rc == 0 and len(stdout) != 0):

        output = stdout[0].split()[1].lower().strip()

        if (output != '' and output == 'no'):

            pass

        else:

            test_failed = True
    else:

        test_failed = True

    if (test_failed):

        fail_l.append('(5.2.6) SSH config: X11 forwarding needs to be disabled')

        msg = "\t  " + text_color_green('X11Forwarding no\n')

        ssh_config_remediation += msg

        ssh_config_fails = True

    else:

        pass_l.append('(5.2.6) SSH config: X11 forwarding is disabled')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #                   5.2.7 Ensure SSH MaxAuthTries is set to 4 or less                  #
    ########################################################################################

    #TODO make this check for whitespace when grepping

    cmd = "grep '^MaxAuthTries' /etc/ssh/sshd_config"

    stdout, stderr, rc = run_cmd(cmd)

    test_failed = False

    if (rc == 0):

        if (stdout != ''):

            l = [0,1,2,3,4]

            output = stdout.splitlines()[0].split()[1].lower().strip()

            n = convert_str_to_int(output)

            if (output != '' and n[0] and n[1][0] in l):
                pass
            else:
                test_failed = True
        else:
            test_failed = True

    else:

        test_failed = True

    if (test_failed):

        fail_l.append('(5.2.7) SSH config: MaxAuthTries needs to be set to 4 or less')

        msg = "\t  " + text_color_green('MaxAuthTries 4\n')

        ssh_config_remediation += msg

        ssh_config_fails = True

    else:

        pass_l.append('(5.2.7) SSH config: MaxAuthTries needs is set to 4 or less')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #                       5.2.8 Ensure SSH IgnoreRhosts is enabled                       #
    ########################################################################################
  
    cmd = "grep -i 'ignorerhosts' /etc/ssh/sshd_config"

    stdout, stderr, rc = run_cmd(cmd)

    test_failed = False
    
    stdout = remove_all_elements_from_list(stdout.splitlines(), ['','\n'], starts_with_l=['#'])

    if (rc == 0 and len(stdout) != 0):

        output = stdout[0].split()[1].lower().strip()

        if (output != '' and output == 'yes'):

            pass

        else:

            test_failed = True
    else:

        test_failed = True

    if (test_failed):

        fail_l.append('(5.2.8) SSH config: IgnoreRhosts needs to be set to yes')

        msg = "\t  " + text_color_green('IgnoreRhosts yes\n')

        ssh_config_remediation += msg

        ssh_config_fails = True

    else:

        pass_l.append('(5.2.8) SSH config: IgnoreRhosts is set to yes')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #                 5.2.9 Ensure SSH HostbasedAuthentication is disabled                 #
    ########################################################################################
  
    cmd = "grep -i '^HostbasedAuthentication' /etc/ssh/sshd_config"

    stdout, stderr, rc = run_cmd(cmd)

    test_failed = False
    
    stdout = remove_all_elements_from_list(stdout.splitlines(), ['','\n'], starts_with_l=['#'])

    if (rc == 0 and len(stdout) != 0):

        output = stdout[0].split()[1].lower().strip()

        if (output != '' and output == 'no'):

            pass

        else:

            test_failed = True
    else:

        test_failed = True

    if (test_failed):

        fail_l.append('(5.2.9) SSH config: HostbasedAuthentication needs to be set to no')

        msg = "\t  " + text_color_green('HostbasedAuthentication no\n')

        ssh_config_remediation += msg

        ssh_config_fails = True

    else:

        pass_l.append('(5.2.9) SSH config: HostbasedAuthentication is set to yes')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #                      5.2.10 Ensure SSH root login is disabled                        #
    ########################################################################################
  
    cmd = "grep -i 'permitrootlogin' /etc/ssh/sshd_config"

    stdout, stderr, rc = run_cmd(cmd)

    test_failed = False
    
    stdout = remove_all_elements_from_list(stdout.splitlines(), ['','\n'], starts_with_l=['#'])

    if (rc == 0 and len(stdout) != 0):

        output = stdout[0].split()[1].lower().strip()

        if (output != '' and output == 'no'):

            pass

        else:

            test_failed = True
    else:

        test_failed = True

    if (test_failed):

        fail_l.append('(5.2.10) SSH config: PermitRootLogin needs to be set to no')

        msg = "\t  " + text_color_green('PermitRootLogin no\n')

        ssh_config_remediation += msg

        ssh_config_fails = True

    else:

        pass_l.append('(5.2.10) SSH config: PermitRootLogin is set to no')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()
    
    ########################################################################################
    #                   5.2.11 Ensure SSH PermitEmptyPasswords is disabled                 #
    ########################################################################################
  
    cmd = "grep -i 'PermitEmptyPasswords' /etc/ssh/sshd_config"

    stdout, stderr, rc = run_cmd(cmd)

    test_failed = False
    
    stdout = remove_all_elements_from_list(stdout.splitlines(), ['','\n'], starts_with_l=['#'])

    if (rc == 0 and len(stdout) != 0):

        output = stdout[0].split()[1].lower().strip()

        if (output != '' and output == 'no'):

            pass

        else:

            test_failed = True
    else:

        test_failed = True

    if (test_failed):

        fail_l.append('(5.2.11) SSH config: PermitEmptyPasswords needs to be set to no')

        msg = "\t  " + text_color_green('PermitEmptyPasswords no\n')

        ssh_config_remediation += msg

        ssh_config_fails = True

    else:

        pass_l.append('(5.2.11) SSH config: PermitEmptyPasswords is set to no')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #                5.2.12 Ensure SSH PermitUserEnvironment is disabled                   #
    ########################################################################################
  
    cmd = "grep -i 'permituserenvironment' /etc/ssh/sshd_config"

    stdout, stderr, rc = run_cmd(cmd)

    test_failed = False
    
    stdout = remove_all_elements_from_list(stdout.splitlines(), ['','\n'], starts_with_l=['#'])

    if (rc == 0 and len(stdout) != 0):

        output = stdout[0].split()[1].lower().strip()

        if (output != '' and output == 'no'):

            pass

        else:

            test_failed = True
    else:

        test_failed = True

    if (test_failed):

        fail_l.append('(5.2.12) SSH config: PermitUserEnvironment needs to be set to no')

        msg = "\t  " + text_color_green('PermitUserEnvironment no\n')

        ssh_config_remediation += msg

        ssh_config_fails = True

    else:

        pass_l.append('(5.2.12) SSH config: PermitUserEnvironment is set to no')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #                     5.2.13 Ensure only strong Ciphers are used                       #
    ########################################################################################
  
    cmd = "sshd -T | grep ciphers"

    stdout, stderr, rc = run_cmd(cmd)

    test_failed = False

    if (rc == 0 and len(stdout) != 0):

        stdout = remove_all_elements_from_list(stdout.splitlines(), ['','\n'], starts_with_l=['#'])

        l = ['3des-cbc','aes128-cbc', 'aes192-cbc', 'aes256-cbc', 'arcfour', \
                'arcfour128', 'arcfour256', 'blowfish-cbc', 'cast128-cbc', 'rijndael-cbc']

        for item in l:

            try:
                if (stdout.index(item.strip().lower()) >= 0):
                    test_failed = True
                    break
            except ValueError:
                pass
    else:

        test_failed = True

    if (test_failed):

        fail_l.append('(5.2.13) SSH config: Strong ciphers need to be used')

        msg = "\t  " + text_color_green('Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\n')

        ssh_config_remediation += msg

        ssh_config_fails = True

    else:

        pass_l.append('(5.2.13) SSH config: Strong ciphers are being used')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #                   5.2.14 Ensure only strong MAC algorithms are used                  #
    ########################################################################################
  
    cmd = 'sshd -T | grep -i "MACs"'

    stdout, stderr, rc = run_cmd(cmd)

    test_failed = False

    if (rc == 0 and len(stdout) != 0):

        stdout = remove_all_elements_from_list(stdout.splitlines(), ['','\n'], starts_with_l=['#'])

        l = ['hmac-md5', 'hmac-md5-96', 'hmac-ripemd160', 'hmac-sha1', \
                'hmac-sha1-96', 'umac-64@openssh.com', 'umac-128@openssh.com', \
                'hmac-md5-etm@openssh.com', 'hmac-md5-96-etm@openssh.com', 'hmac-ripemd160-etm@openssh.com', \
                'hmac-sha1-etm@openssh.com', 'hmac-sha1-96-etm@openssh.com', \
                'umac-64-etm@openssh.com', 'umac-128-etm@openssh.com']

        for item in l:

            try:

                if (stdout.index(item.strip().lower()) >= 0):
                    test_failed = True
                    break

            except ValueError:
                pass
    else:

        test_failed = True

    if (test_failed):

        fail_l.append('(5.2.14) SSH config: Strong MAC algorithms need to be used')

        msg = "\t  " + text_color_green('MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256\n')

        ssh_config_remediation += msg

        ssh_config_fails = True

    else:

        pass_l.append('(5.2.14) SSH config: Strong MAC algorithms are being used')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #               5.2.15 Ensure only strong Key Exchange algorithms are used             #
    ########################################################################################
  
    cmd = 'sshd -T | grep -i kexalgorithms'

    stdout, stderr, rc = run_cmd(cmd)

    test_failed = False

    if (rc == 0 and len(stdout) != 0):

        stdout = remove_all_elements_from_list(stdout.splitlines(), ['','\n'], starts_with_l=['#'])

        l = ['diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1', 'diffie-hellman-group-exchange-sha1']

        for item in l:

            try:

                if (stdout.index(item.strip().lower()) >= 0):
                    test_failed = True
                    break

            except ValueError:
                pass
    else:

        test_failed = True

    if (test_failed):

        fail_l.append('(5.2.15) SSH config: Strong Key Exchange algorithms need to be used')

        msg = "\t  " + text_color_green('KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,' \
                'diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,'\
                'ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256\n')

        ssh_config_remediation += msg

        ssh_config_fails = True

    else:

        pass_l.append('(5.2.15) SSH config: Strong Key Exchange algorithms are being used')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #                 5.2.16 Ensure SSH Idle Timeout Interval is configured                #
    ########################################################################################
  
    #TODO need to check for space when grepping from config
    cmd1 = "grep -i '^clientaliveinterval' /etc/ssh/sshd_config"
    cmd2 = "grep -i '^clientalivecountmax' /etc/ssh/sshd_config"

    stdout1, stderr1, rc1 = run_cmd(cmd1)
    stdout2, stderr2, rc2 = run_cmd(cmd2)

    test_1_failed = False
    test_2_failed = False

    if (rc1 == 0):

        if (stdout1 != ''):

            output = stdout1.splitlines()[0].split()[1].lower().strip()

            n = convert_str_to_int(output)

            if (n[0] and (n[1][0] >= 1 and n[1][0] <= 300)):
                pass
            else:
                test_1_failed = True
        else:
            test_1_failed = True

    else:

        test_1_failed = True

    if (rc2 == 0):

        if (stdout2 != ''):

            output = stdout2.splitlines()[0].split()[1].lower().strip()

            n = convert_str_to_int(output)

            if (n[0] and (n[1][0] <= 3 and n[1][0] >= 0)):
                pass
            else:
                test_2_failed = True
        else:
            test_2_failed = True

    else:

        test_2_failed = True

    if (test_1_failed or test_2_failed):

        fail_l.append('(5.2.16) SSH config: Idle Timeout interval needs to be configured')

        msg = ''

        if (test_1_failed):
            msg += "\t  " + text_color_green('ClientAliveInterval 300\n')

        if (test_2_failed):
            msg += "\t  " + text_color_green('ClientAliveCountMax 0\n')

        ssh_config_remediation += msg

        ssh_config_fails = True

    else:

        pass_l.append('(5.2.16) SSH config: Idle Timeout interval is configured')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #             5.2.17 Ensure SSH LoginGraceTime is set to one minute or less            #
    ########################################################################################
  
    #TODO need to check for space when grepping from config
    #TODO if config uses minutes (e.g 1m) instead of seconds, do appropriate conversions
    cmd1 = "grep -i '^logingracetime' /etc/ssh/sshd_config"

    stdout1, stderr1, rc1 = run_cmd(cmd1)

    test_1_failed = False

    if (rc1 == 0):

        if (stdout1 != ''):

            output = stdout1.splitlines()[0].split()[1].lower().strip()

            n = convert_str_to_int(output)

            if (n[0] and (n[1][0] >= 1 and n[1][0] <= 60)):
                pass
            else:
                test_1_failed = True
        else:
            test_1_failed = True

    else:

        test_1_failed = True


    if (test_1_failed):

        fail_l.append('(5.2.17) SSH config: LoginGraceTime needs to be set to one minute or less')

        msg += "\t  " + text_color_green('LoginGraceTime 60\n')

        ssh_config_remediation += msg

        ssh_config_fails = True

    else:

        pass_l.append('(5.2.17) SSH config: LoginGraceTime is set to one minute or less')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #                         5.2.18 Ensure SSH access is limited                          #
    ########################################################################################
  
    l = ['AllowUsers', 'AllowGroups', 'DenyUsers', 'DenyGroups']

    failed_options = []

    test_failed = False

    cmd = 'sshd -T | grep -i "%s"' % l

    stdout, stderr, rc = run_cmd(cmd)

    stdout = remove_all_elements_from_list(stdout.splitlines(), ['','\n'], starts_with_l=['#'])

    # Separating keywords from arguments

    for i in range(len(stdout)):

        stdout[i] = stdout[i].split()[0].lower()

    if (len(stdout) != 0):

        for option in l:

            try:

                if (stdout.index(option.lower()) >= 0):
                    pass

            except ValueError:
                test_failed = True
                failed_options.append(option)

    else:
        test_failed = True
        failed_options = l

    if (test_failed):

        fail_l.append('(5.2.18) SSH config: SSH Access needs to be limited')

        msg = ''

        for item in failed_options:
            msg += "\t  " + text_color_green('%s <userlist>\n' % item)

        ssh_config_remediation += msg

        ssh_config_fails = True

    else:

        pass_l.append('(5.2.18) SSH config: SSH Access is limited')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #                    5.2.19 Ensure SSH warning banner is configured                    #
    ########################################################################################
  
    cmd = "grep -i 'Banner' /etc/ssh/sshd_config"

    stdout, stderr, rc = run_cmd(cmd)

    test_failed = False
    
    stdout = remove_all_elements_from_list(stdout.splitlines(), ['','\n'], starts_with_l=['#'])

    if (rc == 0 and len(stdout) != 0):

        output = stdout[0].split()[1].lower().strip()

        if (output != '' and output.strip() == '/etc/issue.net'):

            pass

        else:

            test_failed = True
    else:

        test_failed = True

    if (test_failed):

        fail_l.append('(5.2.19) SSH config: Warning banner needs to be configured')

        msg = "\t  " + text_color_green('Banner /etc/issue.net\n')

        ssh_config_remediation += msg

        ssh_config_fails = True

    else:

        pass_l.append('(5.2.19) SSH config: Warning banner is configured')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #                          5.2.20 Ensure SSH PAM is enabled                            #
    ########################################################################################
  
    cmd = "grep -i 'UsePAM' /etc/ssh/sshd_config"

    stdout, stderr, rc = run_cmd(cmd)

    test_failed = False
    
    stdout = remove_all_elements_from_list(stdout.splitlines(), ['','\n'], starts_with_l=['#'])

    if (rc == 0 and len(stdout) != 0):

        output = stdout[0].split()[1].lower().strip()

        if (output != '' and output.strip().lower() == 'yes'):

            pass

        else:

            test_failed = True
    else:

        test_failed = True

    if (test_failed):

        fail_l.append('(5.2.20) SSH config: PAM needs to be enabled')

        msg = "\t  " + text_color_green('UsePAM yes\n')

        ssh_config_remediation += msg

        ssh_config_fails = True

    else:

        pass_l.append('(5.2.20) SSH config: PAM is enabled')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #                   5.2.21 Ensure SSH AllowTcpForwarding is disabled                   #
    ########################################################################################
  
    cmd = "grep -i 'AllowTcpForwarding' /etc/ssh/sshd_config"

    stdout, stderr, rc = run_cmd(cmd)

    test_failed = False
    
    stdout = remove_all_elements_from_list(stdout.splitlines(), ['','\n'], starts_with_l=['#'])

    if (rc == 0 and len(stdout) != 0):

        output = stdout[0].split()[1].lower().strip()

        if (output != '' and output.strip().lower() == 'no'):

            pass

        else:

            test_failed = True
    else:

        test_failed = True

    if (test_failed):

        fail_l.append('(5.2.21) SSH config: AllowTcpForwarding needs to be disabled')

        msg = "\t  " + text_color_green('AllowTcpForwarding no\n')

        ssh_config_remediation += msg

        ssh_config_fails = True

    else:

        pass_l.append('(5.2.21) SSH config: AllowTcpForwarding is disabled')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #                    5.2.22 Ensure SSH MaxStartups is configured                       #
    ########################################################################################
  
    cmd = "grep -i 'MaxStartups' /etc/ssh/sshd_config"

    stdout, stderr, rc = run_cmd(cmd)

    test_failed = False
    
    stdout = remove_all_elements_from_list(stdout.splitlines(), ['','\n'], starts_with_l=['#'])

    if (rc == 0 and len(stdout) != 0):

        output = stdout[0].split()[1].lower().strip()

        if (output != '' and output.strip().lower() == '10:30:60'):

            pass

        else:

            test_failed = True
    else:

        test_failed = True

    if (test_failed):

        fail_l.append('(5.2.22) SSH config: MaxStartups needs to be configured')

        msg = "\t  " + text_color_green('MaxStartups 10:30:60\n')

        ssh_config_remediation += msg

        ssh_config_fails = True

    else:

        pass_l.append('(5.2.22) SSH config: MaxStartups is configured')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #                    5.2.23 Ensure SSH MaxSessions is set to 4 or less                 #
    ########################################################################################
  
    cmd1 = "grep -i '^maxsessions' /etc/ssh/sshd_config"

    stdout1, stderr1, rc1 = run_cmd(cmd1)

    test_1_failed = False

    if (rc1 == 0):

        if (stdout1 != ''):

            output = stdout1.splitlines()[0].split()[1]

            n = convert_str_to_int(output)

            if (n[0] and (n[1][0] >= 1 and n[1][0] <= 4)):
                pass
            else:
                test_1_failed = True
        else:
            test_1_failed = True

    else:

        test_1_failed = True


    if (test_1_failed):

        fail_l.append('(5.2.23) SSH config: MaxSessions needs to be set to 4 or less')

        msg += "\t  " + text_color_green('MaxSessions 4\n')

        ssh_config_remediation += msg

        ssh_config_fails = True

    else:

        pass_l.append('(5.2.23) SSH config: MaxSessions is set to 4 or less')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #                                 PAM Configurations                                   #
    ########################################################################################
  
    pam_config_remediation = ''

    pam_config_fails = False

    pam_config_remediation += color_symbol_debug() + text_color_yellow(' Edit /etc/security/pwquality.conf & add the following parameters:\n\n')

    fl1 = ['/etc/security/pwquality.conf']
    fl2 = ['/etc/pam.d/system-auth', '/etc/pam.d/common-password']

    _fl1 = []
    _fl2 = []

    data_1 = []
    data_2 = []

    pam_config_all = []

    configs_status = []

    invalid_configs = []

    pw_config = [('retry', 3), ('minlen', 14), ('dcredit', -1), ('ucredit', -1), ('ocredit', -1), ('lcredit', -1)]

    for f in fl2:
        if (os.path.isfile(f)):
            _fl2.append(f)

    #parse_pam_configs(fl[0], pw_config)

    for f in _fl2:

        data = read_from_file(f, ['', '\n'])

        if (data[0]):

            data = remove_all_elements_from_list(data[1], starts_with_l=['#'])
            data_2 += data[0].split()    

    # print(data_2)

    if (len(data_2) != 0):

        for item in data_2:

            for c in pw_config:

                index = item.find(c[0])

                # print(c)
                # print(index)
                if (index >= 0):

                    try:
                        keyword = item.split('=')[0]
                        arg = convert_str_to_int(item.split('=')[1])

                        if (arg[0]):
                            pam_config_all.append((keyword, arg[1][0]))

                    except IndexError:
                        pass

    # print(pam_config_all)

    for f in fl1:

        if (os.path.isfile(f)):
            _fl1.append(f)

    for f in _fl1:

        data = read_from_file(f, ['', '\n'])

        if (data[0]):

            data = remove_all_elements_from_list(data[1], starts_with_l=['#'])
            data_1 += data

    # print("Data_1: ", data_1)

    # def search_in_2d_list(l=[], keyword='', keyword_type_str=False,
    #         keyword_type_int=False, keyword_index=0, compare_value=False,
    #         value_index=1, value=-1, convert_to_int=False, partial_match=True):

    for item in data_1:

        for c in pw_config:

            index = item.find(c[0])

            if (index >= 0):

                try:

                    keyword = item.split('=')[0]
                    arg = convert_str_to_int(item.split('=')[1])

                    if (arg[0]):

                        # If no previous keywords found in configs found so far
                        if (search_in_2d_list(pam_config_all, keyword, keyword_type_str=True)[0] == False):
                            pam_config_all.append((keyword, arg[1][0]))

                except IndexError:
                    pass

    pam_config_all = remove_duplicates_from_2d_list(pam_config_all)

    # print(pam_config_all)
    # print(data_1)
    # print(data_2)
    # sys.exit(1)
    # print(pam_config_all)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #             5.3.1 Ensure password creation requirements are configured               #
    ########################################################################################

    for c in pam_config_all:

        if (c[0] == 'minlen'):
            if (c[1] >= 14):
                configs_status.append(('minlen', True))
            else:
                configs_status.append(('minlen', False))

        elif (c[0] == 'retry'):
            if (c[1] == 3):
                configs_status.append(('retry', True))
            else:
                configs_status.append(('retry', False))

        elif (c[0] == 'dcredit'):
            if (c[1] == -1):
                configs_status.append(('dcredit', True))
            else:
                configs_status.append(('dcredit', False))

        elif (c[0] == 'ucredit'):
            if (c[1] == -1):
                configs_status.append(('ucredit', True))
            else:
                configs_status.append(('ucredit', False))

        elif (c[0] == 'ocredit'):
            if (c[1] == -1):
                configs_status.append(('ocredit', True))
            else:
                configs_status.append(('ocredit', False))

        elif (c[0] == 'lcredit'):
            if (c[1] == -1):
                configs_status.append(('lcredit', True))
            else:
                configs_status.append(('lcredit', False))

    # print(configs_status) 

    # def search_in_2d_list(l=[], keyword='', keyword_type_str=False,
    #         keyword_type_int=False, keyword_index=0, compare_value=False,
    #         value_index=1, value=-1, convert_to_int=False, partial_match=True):

    for c in pw_config:
        # print(c[0])
        output = search_in_2d_list(configs_status, c[0], keyword_type_str=True)

        # print(output)
        if (output[0] == False):
            invalid_configs.append(c)

    # print(invalid_configs)

    test_failed = False

    if (len(invalid_configs) != 0):
        test_failed = True

    if (test_failed):

        fail_l.append('(5.3.1) PAM config: Password creation requirements need to be configured')

        msg = ''

        for option in invalid_configs:
            msg += "\t  " + text_color_green('%s = %s\n' % (option[0], option[1]))

        pam_config_remediation += msg

        pam_config_fails = True

    else:

        pass_l.append('(5.3.1) PAM config: Password creation requirements are configured')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #                             Loading PAM configurations                               #
    ########################################################################################

    ## From this point the data gathered are based on function 
    ## validate_line_in_config_with_variable_params() so this data can be reused in other tests

    fl1 = ['/etc/pam.d/password-auth', '/etc/pam.d/system-auth', '/etc/pam.d/common-auth']

    _fl1 = []

    data = []

    for f in fl1:
        if (os.path.isfile(f)):
            _fl1.append(f)

    #parse_pam_configs(fl[0], pw_config)

    for f in _fl1:

        output = read_from_file(f, ['', '\n'])

        if (output[0]):

            data += remove_all_elements_from_list(output[1], starts_with_l=['#'])

    # print(data)
    # sys.exit(0)

    ########################################################################################
    #           5.3.2 Ensure lockout for failed password attempts is configured            #
    ########################################################################################

    config_532 = [ ['auth', 'required', 'pam_faillock.so', 'preauth', 'audit', 'silent', 'deny=5', 'unlock_time=900'], \
            ['auth', 'sufficient','pam_unix.so'], \
            ['auth', '[default=die]', 'pam_faillock.so', 'authfail', 'audit', 'deny=5', 'unlock_time=900'], \
            ['auth', 'sufficient', 'pam_faillock.so', 'authsucc', 'audit', 'deny=5', 'unlock_time=900']]

    #def validate_line_in_config_with_variable_params(line='', params=[], \
    #        fixed_param_indexes=[], delimiter='', fail_if_extra_param=False, trim_whitespace=True):

    missing_configs_l = []

    for c in config_532:

        found = False

        for line in data:

            output = validate_line_in_config_with_variable_params(line, c, [0,1,2])

            if (output[0] == 0):
                found = True
                break

        if (not found):
            missing_configs_l.append(c)

    test_failed = False

    if (len(missing_configs_l) != 0):
        test_failed = True

    if (test_failed):

        fail_l.append('(5.3.2) PAM config: Lockout for failed password attempts needs to be configured')

        msg = ''

        pam_config_remediation += '\n' + color_symbol_debug() + \
                text_color_yellow(' Edit /etc/pam.d/system-auth & add the following parameters:\n\n')

        for line in missing_configs_l:
            msg += "\t  " + text_color_green('%s\n' % convert_list_to_str(line))

        pam_config_remediation += msg

        pam_config_fails = True

    else:

        pass_l.append('(5.3.2) PAM config: Lockout for failed password attempts are configured')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #                       Shadow Password Params Configuration                           #
    ########################################################################################

    remediation_sh_pw_l_sites = color_symbol_debug() + text_color_yellow(' Edit & add the following to /etc/login.defs:\n\n')
    remediation_sh_pw_l_users = color_symbol_debug() + text_color_yellow(' Configure secure shadow password setting by running the following commands:\n\n')

    ########################################################################################
    #                5.4.1.1 Ensure password expiration is 365 days or less                #
    ########################################################################################

    cmd1 = "grep PASS_MAX_DAYS /etc/login.defs"
    cmd2 = "grep -E '^[^:]+:[^!*]' /etc/shadow | cut -d: -f1,5"

    stdout1, stderr1, rc1 = run_cmd(cmd1)
    stdout2, stderr2, rc2 = run_cmd(cmd2)

    test1_failed = False
    test2_failed = False

    stdout1 = remove_all_elements_from_list(stdout1.splitlines(), ['','\n'], starts_with_l=['#'])
    stdout2 = remove_all_elements_from_list(stdout2.splitlines(), ['','\n'], starts_with_l=['#'])

    if (rc1 == 0 and len(stdout1) != 0):

        for line in stdout1:

            days = line.split()[1]

            output = convert_str_to_int(days)

            if (output[0] and output[1][0] <= 365):
                pass
            else:
                test1_failed = True
                break
    else:

        test1_failed = True

    test2_remediation_l = []

    if (rc2 == 0 and len(stdout2) != 0):

        for line in stdout2:

            if (':' in line):
                days = line.split(':')[1]

                output = convert_str_to_int(days)

                if (output[0] and output[1][0] <= 365):
                    pass
                else:
                    test2_failed = True
                    test2_remediation_l.append(line.split(':')[0])
    else:

        test2_failed = True

    if (test1_failed or test2_failed):

        fail_l.append('(5.4.1.1) Password expiration needs to be configured to be 365 days or less')

        msg = ''

        if (test1_failed):

            remediation_sh_pw_l_sites += "\t  " + text_color_green('PASS_MAX_DAYS 365\n')

        if (test2_failed):

            for line in test2_remediation_l:
                remediation_sh_pw_l_users += "\t  " + text_color_orange('sudo chage --maxdays 365 %s\n' % line)

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(5.4.1.1) Password expiration is configured to be 365 days or less')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #           5.4.1.2 Ensure minimum days between password changes is 7 or more          #
    ########################################################################################

    cmd1 = "grep PASS_MIN_DAYS /etc/login.defs"
    cmd2 = "grep -E ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1,4"

    stdout1, stderr1, rc1 = run_cmd(cmd1)
    stdout2, stderr2, rc2 = run_cmd(cmd2)

    test1_failed = False
    test2_failed = False
    
    stdout1 = remove_all_elements_from_list(stdout1.splitlines(), ['','\n'], starts_with_l=['#'])
    stdout2 = remove_all_elements_from_list(stdout2.splitlines(), ['','\n'], starts_with_l=['#'])

    if (rc1 == 0 and len(stdout1) != 0):

        for line in stdout1:

            days = line.split()[1]

            output = convert_str_to_int(days)

            if (output[0] and output[1][0] >= 7):
                pass
            else:
                test1_failed = True
                break
    else:

        test1_failed = True

    test2_remediation_l = []

    if (rc2 == 0 and len(stdout2) != 0):

        for line in stdout2:

            if (':' in line):
                days = line.split(':')[1]

                output = convert_str_to_int(days)

                if (output[0] and output[1][0] >= 7):
                    pass
                else:
                    test2_failed = True
                    test2_remediation_l.append(line.split(':')[0])
    else:

        test2_failed = True

    if (test1_failed or test2_failed):

        fail_l.append('(5.4.1.2) Minimum days between password changes needs to be 7 or more')

        msg = ''

        if (test1_failed):

            remediation_sh_pw_l_sites += "\t  " + text_color_green('PASS_MIN_DAYS 7\n')

        if (test2_failed):

            for line in test2_remediation_l:
                remediation_sh_pw_l_users += "\t  " + text_color_orange('sudo chage --mindays 7 %s\n' % line)

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(5.4.1.2) Minimum days between password changes is configured to be 7 or more')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #             5.4.1.3 Ensure password expiration warning days is 7 or more             #
    ########################################################################################

    cmd1 = "grep 'PASS_WARN_AGE' /etc/login.defs"
    cmd2 = "grep -E '^[^:]+:[^\!*]' /etc/shadow | cut -d: -f1,6"

    stdout1, stderr1, rc1 = run_cmd(cmd1)
    stdout2, stderr2, rc2 = run_cmd(cmd2)

    test1_failed = False
    test2_failed = False
    
    stdout1 = remove_all_elements_from_list(stdout1.splitlines(), ['','\n'], starts_with_l=['#'])
    stdout2 = remove_all_elements_from_list(stdout2.splitlines(), ['','\n'], starts_with_l=['#'])

    if (rc1 == 0 and len(stdout1) != 0):

        for line in stdout1:

            days = line.split()[1]

            output = convert_str_to_int(days)

            if (output[0] and output[1][0] >= 7):
                pass
            else:
                test1_failed = True
                break
    else:

        test1_failed = True

    test2_remediation_l = []

    if (rc2 == 0 and len(stdout2) != 0):

        for line in stdout2:

            if (':' in line):
                days = line.split(':')[1]

                output = convert_str_to_int(days)

                if (output[0] and output[1][0] >= 7):
                    pass
                else:
                    test2_failed = True
                    test2_remediation_l.append(line.split(':')[0])
    else:

        test2_failed = True

    if (test1_failed or test2_failed):

        fail_l.append('(5.4.1.3) Password expiration warning needs to be 7 or more')

        msg = ''

        if (test1_failed):

            remediation_sh_pw_l_sites += "\t  " + text_color_green('PASS_WARN_AGE 7\n')

        if (test2_failed):

            for line in test2_remediation_l:
                remediation_sh_pw_l_users += "\t  " + text_color_orange('sudo chage --warndays 7 %s\n' % line)

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(5.4.1.3) Password expiration warning is atleast 7 or more')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #               5.4.1.4 Ensure inactive password lock is 30 days or less               #
    ########################################################################################

    cmd1 = "useradd -D | grep INACTIVE"
    cmd2 = "grep -E '^[^:]+:[^\!*]' /etc/shadow | cut -d: -f1,6"

    stdout1, stderr1, rc1 = run_cmd(cmd1)
    stdout2, stderr2, rc2 = run_cmd(cmd2)

    test1_failed = False
    test2_failed = False
    
    stdout1 = remove_all_elements_from_list(stdout1.splitlines(), ['','\n'], starts_with_l=['#'])
    stdout2 = remove_all_elements_from_list(stdout2.splitlines(), ['','\n'], starts_with_l=['#'])

    if (rc1 == 0 and len(stdout1) != 0):

        for line in stdout1:

            days = line.split('=')[1]

            output = convert_str_to_int(days)

            if (output[0] and (output[1][0] >= 7 and output[1][0] <= 30)):
                pass
            else:
                test1_failed = True
                break
    else:

        test1_failed = True

    test2_remediation_l = []

    if (rc2 == 0 and len(stdout2) != 0):

        for line in stdout2:

            if (':' in line):
                days = line.split(':')[1]

                output = convert_str_to_int(days)

                if (output[0] and (output[1][0] >= 7 and output[1][0] <= 30)):
                    pass
                else:
                    test2_failed = True
                    test2_remediation_l.append(line.split(':')[0])
    else:

        test2_failed = True

    if (test1_failed or test2_failed):

        fail_l.append('(5.4.1.4) Inactive password lock needs to be set to 30 days or more')

        msg = ''

        if (test1_failed):

            remediation_sh_pw_l_sites += "\t  " + text_color_green('PASS_WARN_AGE 7\n')

        if (test2_failed):

            for line in test2_remediation_l:
                remediation_sh_pw_l_users += "\t  " + text_color_orange('sudo chage --warndays 7 %s\n' % line)

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(5.4.1.4) Inactive password lock is set to 30 days or more')

    if (len(remediation_sh_pw_l_sites) > 0):
        remediation_msg_l.append(remediation_sh_pw_l_sites)

    if (len(remediation_sh_pw_l_users) > 0):
        remediation_msg_l.append(remediation_sh_pw_l_users)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #                       END of Shadow Password Params Configuration                    #
    ########################################################################################

    ########################################################################################
    #           5.4.1.5 Ensure all users last password change date is in the past          #
    ########################################################################################

    current_date = date.today()

    invalid_user_l = []

    user_l = get_list_of_all_users()

    # time_diff = time.perf_counter()

    test_failed = False

    for user in user_l:

        cmd = "sudo chage --list %s | grep '^Last pass' | cut -d':' -f2" % user
        stdout, stderr, rc = run_cmd(cmd)
        date_past = stdout.strip().replace(',', '')

        # print(date_past)
        try:
            month = convert_month_str_to_int(date_past.split()[0])
        except (ValueError, IndexError):
            continue

        if (type(month) != int):
            invalid_user_l.append(user)
            test_failed = True
            break

        day = convert_str_to_int(date_past.split()[1])

        if (not day[0]):
            invalid_user_l.append(user)
            test_failed = True
            break
        else:
            day = day[1][0]

        try:
            year = convert_str_to_int(date_past.split()[2])
        except (ValueError, IndexError):
            continue

        if (not year[0]):
            invalid_user_l.append(user)
            test_failed = True
            break
        else:
            year = year[1][0]

        # print(year)
        # print(type(year))
        # print(month)
        # print(type(month))
        # print(day)
        # print(type(day))
        # sys.exit(1)

        day_diff = compare_with_date(day, month, year, current_date.day, current_date.month, current_date.year)

        if (day_diff <= 0):
            invalid_user_l.append(user)
            test_failed = True
        else:
            pass

    if (test_failed):

        fail_l.append('(5.4.1.5) Last password of some users needs to be set to a date in the past')

        msg = '\n' + color_symbol_debug() + text_color_yellow(' Last password of the following users needs to be double checked:\n\n')

        for user in invalid_user_l:
            msg += "\t  " + text_color_green('%s\n' % user)

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(5.4.1.5) Last password of all users is set in the past')

    # time_dff = time.perf_counter() - time_diff
    # print(time_diff)

    ########################################################################################
    #                       5.4.2 Ensure system accounts are secured                       #
    ########################################################################################

    cmd = 'awk -F: \'($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && ' + \
            '$1!~/^\+/ && $3<\'"$(awk \'/^\s*UID_MIN/{print $2}\' /etc/login.defs)"\' && ' + \
            '$7!="\'"$(which nologin)"\'" && $7!="/bin/false") {print}\' /etc/passwd | cut -d: -f1'

    test_failed = False

    stdout, stderr, rc = run_cmd(cmd)

    unused_accounts = []

    if (rc == 0 and stdout.strip() != ''):

        unused_accounts = remove_all_elements_from_list(stdout.splitlines(), ['','\n'], starts_with_l=['#'])

        if (len(unused_accounts) != 0):
            test_failed = True
        else:
            pass
    else:
        test_failed = True

    if (test_failed):

        fail_l.append('(5.4.2) System accounts that are not being used need to be locked')

        msg = '\n' + color_symbol_debug() + text_color_yellow(' Run the following commands to lockout inactive system accounts:\n\n')

        for user in unused_accounts:
            msg += "\t  " + text_color_orange('sudo usermod -L %s\n' % user)

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(5.4.2) Unused system accounts are being locked')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #               5.4.3 Ensure default group for the root account is GID 0               #
    ########################################################################################

    cmd = 'grep "^root:" /etc/passwd | cut -f4 -d:'

    test_failed = False

    stdout, stderr, rc = run_cmd(cmd)

    unused_accounts = []

    if (rc == 0 and stdout.strip() != ''):

        output = convert_str_to_int(stdout.strip()[0])

        if (output[0] and output[1][0] != 0):
            test_failed = True

    if (test_failed):

        fail_l.append('(5.4.3) Default group (GID) for root accounts needs to be set to 0')

        msg = '\n' + color_symbol_debug() + text_color_yellow(' Run the following commands to lockout inactive system accounts:\n\n')
        msg += "\t  " + text_color_orange('sudo usermod -g 0 root\n' % user)

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(5.4.3) Default group (GID) for root accounts is set to set to 0')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ########################################################################################
    #               5.4.4 Ensure default user umask is 027 or more restrictive             #
    ########################################################################################

    test_failed = False

    fl = []

    user_l = os.listdir('/home')

    for user in user_l:

        h_dir = os.path.join('/home', user)

        profile = os.path.join(h_dir, '.profile')

        if (os.path.isfile(profile)):
            fl.append(profile)

        shell_paths_l = [os.path.join(h_dir, '.bashrc'), os.path.join(h_dir, '.zshrc'), \
                os.path.join(h_dir, '.csh')]

        for s in shell_paths_l:
            if (os.path.isfile(s)):
                fl.append(s)

    if (os.path.isfile('/root/.profile')):
        fl.append('/root/.profile')

    shell_paths_l = [os.path.join('/root', '.bashrc'), os.path.join('/root', '.zshrc'), \
            os.path.join('/root', '.csh')]

    for s in shell_paths_l:
        if (os.path.isfile(s)):
            fl.append(s)

    if (os.path.isfile('/etc/bashrc')):
        fl.append('/etc/bashrc')

    if (os.path.isfile('/etc/zshrc')):
        fl.append('/etc/bashrc')

    if (os.path.isfile('/etc/profile')):
        fl.append('/etc/bashrc')

    files_found = os.listdir('/etc/profile.d/') 

    for f in files_found:
        if (f.endswith('sh')):
            fl.append(f)

    fl = list(set(fl))

    # print(fl)
    # sys.exit(1)

    found_failed_l = []
    found_passed_l = []
    not_found_l = []

    for f in fl:

        data = read_from_file(f, ['', '\n'])

        if (data[0]):

            data = remove_all_elements_from_list(data[1], starts_with_l=['#'])

            found = False
            failed = False

            for line in data:

                umask = ''

                if (line.strip().startswith('umask')):

                    umask = line.strip().split()[1]

                    user = umask[0]
                    group = umask[1]
                    other = umask[2]

                    output = convert_str_to_int(user)

                    if output[0]:
                        user = output[1][0]
                    else:
                        break

                    output = convert_str_to_int(group)

                    if output[0]:
                        group = output[1][0]
                    else:
                        break

                    output = convert_str_to_int(other)

                    if output[0]:
                        other = output[1][0]
                    else:
                        break

                    found = True

                    if (user != 0):
                        failed = True
                        break

                    if (group == 1 or group == 0):
                        failed = True
                        break

                    if (other != 7):
                        failed = True
                        break

            if (found and failed):
                found_failed_l.append(f)
            elif (found and not failed):
                found_passed_l.append(f)
            else:
                not_found_l.append(f)
        else:
            not_found_l.append(f)

    # print(found_failed_l)
    # print(found_passed_l)
    # print(not_found_l)

    if (len(not_found_l) != 0 or len(found_failed_l) != 0):
        test_failed = True

    if (test_failed):

        fail_l.append('(5.4.4) Default usermask needs to be set to 027 or more restrictive')

        msg = ''

        msg += '\n' + color_symbol_debug() + text_color_yellow(" Run these commands to remove excessive permissions from the following files:\n\n")
        if (len(not_found_l) != 0):

            for f in not_found_l:
                msg += "\t  " + text_color_orange('sudo umask 027 %s\n' % f)

        if (len(found_failed_l) != 0):

            for f in found_failed_l:
                msg += "\t  " + text_color_orange('sudo umask 027 %s\n' % f)

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(5.4.4) Default usermask is be set to 027 or more restrictive')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #      5.4.5 Ensure default user shell timeout is 900 seconds or less     #
    ###########################################################################

    test_failed = False

    fl = ['/etc/profile', '/etc/bashrc', '/etc/zshrc']

    unset_l = []
    set_incorrect_l = []

    for f in fl:

        found = False
        incorrect = False

        data = read_from_file(f, ['', '\n'])

        if (data[0]):

            data = remove_all_elements_from_list(data[1], starts_with_l=['#'])

            for line in data:

                try:
                    if (line.strip().startswith('TMOUT')):

                        found = True

                        if (line.index('=') >= 0):

                            output = convert_str_to_int(line.strip().split('=')[1])

                            if (output[0] and output[1][0] <= 900):
                                break
                            else:
                                set_incorrect_l.append(f)
                                incorrect = True
                                break
                        else:
                            set_incorrect_l.append(f)
                            incorrect = True
                            break
                    else:
                        unset_l.append(f)
                        break
                            

                except ValueError:
                    pass

    if (len(unset_l) != 0 or len(set_incorrect_l) != 0):
        test_failed = True

    if (test_failed):

        fail_l.append('(5.4.5) Default user shell timeout needs to be set to 900 or less')

        msg = ''

        if (len(unset_l) != 0):

            msg += '\n' + color_symbol_debug() + text_color_yellow(" Set default shell timeout to 900 " + \
                    "or less ('TMOUT=900') for the following files:\n\n")

            for f in unset_l:
                msg += "\t  " + text_color_green('%s\n' % f)

        if (len(set_incorrect_l) != 0):
            msg += '\n' + color_symbol_debug() + text_color_yellow(" Update the" + \
                    " value to 900 or less ('TMOUT=900') for the following files:\n\n")

            for f in set_incorrect_l:
                msg += "\t  " + text_color_green('%s\n' % f)

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(5.4.5) Default user shell timeout is set to 900 or less')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #            5.6 Ensure access to the su command is restricted            #
    ###########################################################################

    # TODO: Check and validate whether required admin users are in wheel group

    test_failed = True

    fl = ['/etc/pam.d/su']

    c = ['auth', 'required', 'pam_wheel.so', 'use_uid']

    for f in fl:

        data = read_from_file(f, ['', '\n'])

        if (data[0]):

            data = remove_all_elements_from_list(data[1], starts_with_l=['#'])

            for line in data:

                output = validate_line_in_config_with_variable_params(line, c, [0,1,2,3])
            
                if (output[0] == 0):
                    test_failed = False
                    break

    if (test_failed):

        fail_l.append('(5.6) Access to su command need to be restricted')

        msg = ''

        msg += '\n' + color_symbol_debug() + text_color_yellow(" Add the following " + \
                "to /etc/pam.d/su: \n\n")

        msg += "\t  " + text_color_green('auth required pam_wheel.so use_uid\n')

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(5.6) Access to su command is being restricted')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #                 File Permission & Owner Remediations                    #
    ###########################################################################

    msg = '\n' + color_symbol_debug() + text_color_yellow(" Configure secure file permissions:\n")
    perm_remediation_l = [msg]

    msg = '\n' + color_symbol_debug() + text_color_yellow(" Configure owner to root only for the following files:\n")
    owner_remediation_l = [msg]


    ###########################################################################
    #         6.1.2 Ensure permissions on /etc/passwd are configured          #
    ###########################################################################

    test_failed = False

    f = '/etc/passwd'

    incorrect_perm = False
    incorrect_owner = False

    if (os.path.isfile(f)):

        user_perm, group_perm, other_perm = get_file_permission(f)

        if (user_perm == 6 and group_perm == 4 and other_perm == 4):
            pass
        else:
            test_failed = True
            incorrect_perm = True

        attrs = os.stat(f)

        uid = attrs.st_uid
        gid = attrs.st_gid

        if (uid == 0 and gid == 0):
            pass
        else:
            test_failed = True
            incorrect_owner = True

    if (test_failed):

        fail_l.append('(6.1.2) Secure permissions need to be configured for /etc/passwd')

        if (incorrect_perm):
            perm_remediation_l.append(text_color_orange("\t  sudo chmod 644 /etc/passwd"))

        if (incorrect_owner):
            owner_remediation_l.append(text_color_orange("\t  sudo chown root:root /etc/passwd"))

    else:

        pass_l.append('(6.1.2) Secure permissions are configured for /etc/passwd')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #         6.1.3 Ensure permissions on /etc/shadow are configured          #
    ###########################################################################

    test_failed = False

    f = '/etc/shadow'

    incorrect_perm = False
    incorrect_owner = False

    if (os.path.isfile(f)):

        user_perm, group_perm, other_perm = get_file_permission(f)

        if (user_perm == 6 and group_perm == 4 and other_perm == 4):
            pass
        else:
            test_failed = True
            incorrect_perm = True

        attrs = os.stat(f)

        uid = attrs.st_uid
        gid = attrs.st_gid

        if (uid == 0 and gid == 0):
            pass
        else:
            test_failed = True
            incorrect_owner = True

    if (test_failed):

        fail_l.append('(6.1.3) Secure permissions need to be configured for %s' % f)

        if (incorrect_perm):
            perm_remediation_l.append(text_color_orange("\t  sudo chmod 644 %s" % f))

        if (incorrect_owner):
            owner_remediation_l.append(text_color_orange("\t  sudo chown root:root %s" %  f))
    else:

        pass_l.append('(6.1.3) Secure permissions are configured for %s' % f)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #         6.1.4 Ensure permissions on /etc/group are configured           #
    ###########################################################################

    test_failed = False

    f = '/etc/group'

    incorrect_perm = False
    incorrect_owner = False

    if (os.path.isfile(f)):

        user_perm, group_perm, other_perm = get_file_permission(f)

        if (user_perm == 6 and group_perm == 4 and other_perm == 4):
            pass
        else:
            test_failed = True
            incorrect_perm = True

        attrs = os.stat(f)

        uid = attrs.st_uid
        gid = attrs.st_gid

        if (uid == 0 and gid == 0):
            pass
        else:
            test_failed = True
            incorrect_owner = True

    if (test_failed):

        fail_l.append('(6.1.6) Secure permissions need to be configured for %s' % f)

        if (incorrect_perm):
            perm_remediation_l.append(text_color_orange("\t  sudo chmod 644 %s" % f))

        if (incorrect_owner):
            owner_remediation_l.append(text_color_orange("\t  sudo chown root:root %s" %  f))

    else:

        pass_l.append('(6.1.4) Secure permissions are configured for %s' % f)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #         6.1.5 Ensure permissions on /etc/passwd- are configured         #
    ###########################################################################

    test_failed = False

    f = '/etc/gshadow'

    incorrect_perm = False
    incorrect_owner = False

    if (os.path.isfile(f)):

        user_perm, group_perm, other_perm = get_file_permission(f)

        if (user_perm == 6 and group_perm == 4 and other_perm == 0):
            pass
        else:
            test_failed = True
            incorrect_perm = True

        attrs = os.stat(f)

        uid = attrs.st_uid
        gid = attrs.st_gid

        if (uid == 0 and gid == 0):
            pass
        else:
            test_failed = True
            incorrect_owner = True

    if (test_failed):

        fail_l.append('(6.1.5) Secure permissions need to be configured for %s' % f)

        if (incorrect_perm):
            perm_remediation_l.append(text_color_orange("\t  sudo chmod 640 %s" % f))

        if (incorrect_owner):
            owner_remediation_l.append(text_color_orange("\t  sudo chown root:root %s" %  f))
    else:

        pass_l.append('(6.1.5) Secure permissions are configured for %s' % f)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #         6.1.6 Ensure permissions on /etc/passwd- are configured         #
    ###########################################################################

    test_failed = False

    f = '/etc/passwd-'

    incorrect_perm = False
    incorrect_owner = False

    if (os.path.isfile(f)):

        user_perm, group_perm, other_perm = get_file_permission(f)

        if (user_perm == 6 and group_perm == 0 and other_perm == 0):
            pass
        else:
            test_failed = True
            incorrect_perm = True

        attrs = os.stat(f)

        uid = attrs.st_uid
        gid = attrs.st_gid

        if (uid == 0 and gid == 0):
            pass
        else:
            test_failed = True
            incorrect_owner = True

    if (test_failed):

        fail_l.append('(6.1.6) Secure permissions need to be configured for %s' % f)

        if (incorrect_perm):
            perm_remediation_l.append(text_color_orange("\t  sudo chmod 600 %s" % f))

        if (incorrect_owner):
            owner_remediation_l.append(text_color_orange("\t  sudo chown root:root %s" %  f))
    else:

        pass_l.append('(6.1.6) Secure permissions are configured for %s' % f)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #         6.1.7 Ensure permissions on /etc/shadow- are configured         #
    ###########################################################################

    test_failed = False

    f = '/etc/shadow-'

    incorrect_perm = False
    incorrect_owner = False

    if (os.path.isfile(f)):

        user_perm, group_perm, other_perm = get_file_permission(f)

        if (user_perm == 6 and group_perm == 4 and other_perm == 0):
            pass
        else:
            test_failed = True
            incorrect_perm = True

        attrs = os.stat(f)

        uid = attrs.st_uid
        gid = attrs.st_gid

        if (uid == 0 and gid == 0):
            pass
        else:
            test_failed = True
            incorrect_owner = True

    if (test_failed):

        fail_l.append('(6.1.7) Secure permissions need to be configured for %s' % f)

        if (incorrect_perm):
            perm_remediation_l.append(text_color_orange("\t  sudo chmod 640 %s" % f))

        if (incorrect_owner):
            owner_remediation_l.append(text_color_orange("\t  sudo chown root:root %s" %  f))
    else:

        pass_l.append('(6.1.7) Secure permissions are configured for %s' % f)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #         6.1.8 Ensure permissions on /etc/group- are configured          #
    ###########################################################################

    test_failed = False

    f = '/etc/group-' 

    incorrect_perm = False
    incorrect_owner = False

    if (os.path.isfile(f)):

        user_perm, group_perm, other_perm = get_file_permission(f)

        if (user_perm == 6 and group_perm == 4 and other_perm == 4):
            pass
        else:
            test_failed = True
            incorrect_perm = True

        attrs = os.stat(f)

        uid = attrs.st_uid
        gid = attrs.st_gid

        if (uid == 0 and gid == 0):
            pass
        else:
            test_failed = True
            incorrect_owner = True

    if (test_failed):

        fail_l.append('(6.1.8) Secure permissions need to be configured for %s' % f)

        if (incorrect_perm):
            perm_remediation_l.append(text_color_orange("\t  sudo chmod 644 %s" % f))

        if (incorrect_owner):
            owner_remediation_l.append(text_color_orange("\t  sudo chown root:root %s" %  f))
    else:

        pass_l.append('(6.1.8) Secure permissions are configured for %s' % f)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #         6.1.9 Ensure permissions on /etc/gshadow- are configured        #
    ###########################################################################

    test_failed = False

    f = '/etc/gshadow-'

    incorrect_perm = False
    incorrect_owner = False

    if (os.path.isfile(f)):

        user_perm, group_perm, other_perm = get_file_permission(f)

        if (user_perm == 6 and group_perm == 4 and other_perm == 0):
            pass
        else:
            test_failed = True
            incorrect_perm = True

        attrs = os.stat(f)

        uid = attrs.st_uid
        gid = attrs.st_gid

        if (uid == 0 and gid == 0):
            pass
        else:
            test_failed = True
            incorrect_owner = True

    if (test_failed):

        fail_l.append('(6.1.9) Secure permissions need to be configured for %s' % f)

        if (incorrect_perm):
            perm_remediation_l.append(text_color_orange("\t  sudo chmod 640 %s" % f))

        if (incorrect_owner):
            owner_remediation_l.append(text_color_orange("\t  sudo chown root:root %s" %  f))
    else:

        pass_l.append('(6.1.9) Secure permissions are configured for %s' % f)

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    #TODO Remaining CIS Checks starting from Page#499

    ###########################################################################
    #                6.1.10 Ensure no world writable files exist              #
    ###########################################################################

    cmd = "df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -type f -xdev -perm -002 2>/dev/null"

    stdout, stderr, rc = run_cmd(cmd)

    test_failed = False

    if (stdout.strip() != ''):

        output = stdout.strip().split('\n')

        if (len(output) != 0):
            test_failed = True

    if (test_failed):

        fail_l.append('(6.1.10) Ensure no world writable files exist')

        msg = '\n' + color_symbol_debug() + text_color_yellow(' Run the following commands to correct the permissions on world writable files:\n\n')

        for f in output:
            msg += "\t  " + text_color_orange('sudo chmod o-w %s\n' % f)

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(6.1.10) Ensure no world writable files exist')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #            6.1.11 Ensure no unowned files or directories exist          #
    ###########################################################################

    cmd = "df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser 2>/dev/null"

    stdout, stderr, rc = run_cmd(cmd)

    test_failed = False

    if (stdout.strip() != ''):

        output = stdout.strip().split('\n')

        if (len(output) != 0):
            test_failed = True

    if (test_failed):

        fail_l.append('(6.1.11) Ensure no unowned files or directories exist')

        msg = '\n' + color_symbol_debug() + text_color_yellow(' Run the following commands to remove files of users that are no longer on the system:\n\n')

        for f in output:
            msg += "\t  " + text_color_orange('sudo rm -rf %s\n' % f)

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(6.1.11) Ensure no unowned files or directories exist')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #           6.1.12 Ensure no ungrouped files or directories exist         #
    ###########################################################################

    cmd = "df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser 2>/dev/null"

    stdout, stderr, rc = run_cmd(cmd)

    test_failed = False

    if (stdout.strip() != ''):

        output = stdout.strip().split('\n')

        if (len(output) != 0):
            test_failed = True

    if (test_failed):

        fail_l.append('(6.1.12) Ensure no ungrouped files or directories exist')

        msg = '\n' + color_symbol_debug() + text_color_yellow(' Run the following commands to remove files of groups that are no longer on the system:\n\n')

        for f in output:
            msg += "\t  " + text_color_orange('sudo rm -rf %s\n' % f)

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(6.1.12) Ensure no ungrouped files or directories exist')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #                6.2.1 Ensure password fields are not empty               #
    ###########################################################################

    cmd = "cat /etc/shadow | awk -F: '($2 == \"!\") {print $1}'"

    stdout, stderr, rc = run_cmd(cmd)

    unused_accounts = []

    test_failed = False

    if (stdout.strip() != ''):

        output = stdout.strip().split('\n')

        if (len(output) != 0):
            test_failed = True
            unused_accounts = output

    cmd = "cat /etc/shadow | awk -F: '($2 == "") {print $1}'"

    stdout, stderr, rc = run_cmd(cmd)

    if (stdout.strip() != ''):

        output = stdout.strip().split('\n')

        if (len(output) != 0):

            test_failed = True

            for acc in output:
                unused_accounts.append(acc)

    unused_accounts = list(set(unused_accounts))

    if (test_failed):

        fail_l.append('(6.2.1) Ensure password fields are not empty')

        msg = '\n' + color_symbol_debug() + text_color_yellow(' Run the following commands to set a password for accounts that don\'t have one\n\n')

        for acc in unused_accounts:
            msg += "\t  " + text_color_orange('sudo passwd -l %s\n' % acc)

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(6.2.1) Ensure password fields are not empty')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #          6.2.2 Ensure no legacy "+" entries exist in /etc/passwd        #
    ###########################################################################

    cmd = "grep -E '^\+:' /etc/passwd"

    stdout, stderr, rc = run_cmd(cmd)

    test_failed = False

    unused_accounts = []

    if (stdout.strip() != ''):

        unused_accounts = stdout.strip().split('\n')

        if (len(unused_accounts) != 0):
            test_failed = True

    if (test_failed):

        fail_l.append('(6.2.2) Ensure no legacy "+" entries exist in /etc/passwd')

        msg = '\n' + color_symbol_debug() + text_color_yellow(' The following accounts need to be removed from /etc/passwd\n\n')

        for acc in unused_accounts:
            msg += "\t  " + text_color_orange('userdel -r %s\n' % acc)

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(6.2.2) Ensure password fields are not empty')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #           6.2.3 Ensure no legacy "+" entries exist in /etc/shadow       #
    ###########################################################################

    cmd = "grep -E '^\+:' /etc/shadow"

    stdout, stderr, rc = run_cmd(cmd)

    test_failed = False

    unused_accounts = []

    if (stdout.strip() != ''):

        unused_accounts = stdout.strip().split('\n')

        if (len(unused_accounts) != 0):
            test_failed = True

    if (test_failed):

        fail_l.append('(6.2.3) Ensure no legacy "+" entries exist in /etc/shadow')

        msg = '\n' + color_symbol_debug() + text_color_yellow(' The following accounts need to be removed from /etc/shadow\n\n')

        for acc in unused_accounts:
            msg += "\t  " + text_color_orange('userdel -r %s\n' % acc)

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(6.2.3) Ensure no legacy "+" entries exist in /etc/shadow')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #           6.2.4 Ensure no legacy "+" entries exist in /etc/group        #
    ###########################################################################

    cmd = "grep -E '^\+:' /etc/group"

    stdout, stderr, rc = run_cmd(cmd)

    test_failed = False

    unused_accounts = []

    if (stdout.strip() != ''):

        unused_accounts = stdout.strip().split('\n')

        if (len(unused_accounts) != 0):
            test_failed = True

    if (test_failed):

        fail_l.append('(6.2.4) Ensure no legacy "+" entries exist in /etc/group')

        msg = '\n' + color_symbol_debug() + text_color_yellow(' The following accounts need to be removed from /etc/group\n\n')

        for acc in unused_accounts:
            msg += "\t  " + text_color_orange('groupdel %s\n' % acc)

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(6.2.4) Ensure no legacy "+" entries exist in /etc/group')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #               6.2.5 Ensure root is the only UID 0 account               #
    ###########################################################################

    cmd = "grep -E '^\+:' /etc/group"

    stdout, stderr, rc = run_cmd(cmd)

    test_failed = False

    unused_accounts = []

    if (stdout.strip() != ''):

        unused_accounts = stdout.strip().split('\n')

        if (len(unused_accounts) == 0 or len(unused_accounts) > 1):

            test_failed = True

            if ('root' in unused_accounts):
                unused_accounts.pop('root')

    if (test_failed):

        fail_l.append('(6.2.5) Ensure root is the only UID 0 account')

        msg = '\n' + color_symbol_debug() + text_color_yellow(' UID 0 is reserved for root user, therefore the following accounts need to be removed: \n\n')

        for acc in unused_accounts:
            msg += "\t  " + text_color_orange('userdel -r %s\n' % acc)

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(6.2.5) Ensure root is the only UID 0 account')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ###########################################################################
    #                   6.2.6 Ensure root PATH integrity                      #
    ###########################################################################
    #TODO This has been skipped for now, will get back to it later

    """
    cmd = "grep -E '^\+:' /etc/group"

    stdout, stderr, rc = run_cmd(cmd)

    test_failed = False

    unused_accounts = []

    if (stdout.strip() != ''):

        unused_accounts = stdout.strip().split('\n')

        if (len(unused_accounts) == 0 or len(unused_accounts) > 1):

            test_failed = True

            if ('root' in unused_accounts):
                unused_accounts.pop('root')

    if (test_failed):

        fail_l.append('(6.2.6) Ensure root is the only UID 0 account')

        msg = '\n' + color_symbol_debug() + text_color_yellow(' UID 0 is reserved for root user, therefore the following accounts need to be removed: \n\n')

        for acc in unused_accounts:
            msg += "\t  " + text_color_green('%s\n' % acc)

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(6.2.6) Ensure root is the only UID 0 account')
    """


    ###########################################################################
    #               6.2.7 Ensure all users home directories exist             #
    ###########################################################################

    cmd = "cat /etc/passwd | grep -E -v '/usr/bin/nologin|/bin/false' | awk -F: '{print $1,$3}' | awk {'if ($2 >= 1000) print $1'}"

    stdout, stderr, rc = run_cmd(cmd)

    test_failed = False

    accounts = []

    accounts_without_dir = []

    if (stdout.strip() != ''):

        accounts = stdout.strip().split('\n')

        if (len(accounts) == 0 or len(accounts) >= 1):

            for acc in  accounts:

                if (not os.path.isdir('/home/%s' % acc)):

                    accounts_without_dir.append(acc)

        if (len(accounts_without_dir) > 0):
            test_failed = True

    if (test_failed):

        fail_l.append('(6.2.7) Ensure all users home directories exist')

        msg = '\n' + color_symbol_debug() + text_color_yellow(' Run the following commands to create home directory for the following users: \n\n')

        for acc in accounts_without_dir:
            msg += "\t  " + text_color_orange('useradd -m %s\n' % acc)

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(6.2.7) Ensure all users home directories exist')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ################################################################################
    # 6.2.8 Ensure users home directories permissions are 750 or more restrictive  #
    ################################################################################

    cmd = "ls /home/ | awk '{print }'"

    stdout, stderr, rc = run_cmd(cmd)

    test_failed = False

    home_dir_l = []

    error_l = []

    if (stdout.strip() != ''):

        user_l = stdout.strip().split('\n')

        for user in user_l:

            home_dir_l.append(os.path.join('/home/%s' % user))

    home_dir_l.sort()

    for path in home_dir_l:

        user_perm, group_perm, other_perm = get_file_permission(path)

        # print(path)
        # print(user_perm)
        # print(group_perm)
        # print(other_perm)
        # print()

        if (not (user_perm == 7 and group_perm <= 5 and other_perm == 0)):
            error_l.append(path)

    if (len(error_l) != 0):

        test_failed = True

    if (test_failed):

        fail_l.append('(6.2.8) Ensure users home directories permissions are 750 or more restrictive')

        msg = '\n' + color_symbol_debug() + text_color_yellow(' Run the following commands to correct home dir permissions: \n\n')

        for home_dir in error_l:
            msg += "\t  " + text_color_orange('sudo chmod -R 750 %s\n' % home_dir)

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(6.2.8) Ensure users home directories permissions are 750 or more restrictive')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ################################################################################
    #                6.2.9 Ensure users own their home directories                 #
    ################################################################################

    cmd = "cat /etc/passwd | grep -E -v '/usr/bin/nologin|/bin/false' | awk -F: '{print $1,$3,$6}' | awk {'if ($2 >= 1000) print'}"

    stdout, stderr, rc = run_cmd(cmd)

    test_failed = False

    home_dir_l = []

    error_l = [] # username, userid, home_dir

    dir_no_exist = [] # username, home_dir

    if (stdout.strip() != ''):

        records = stdout.strip().split('\n')

        # print(records)

        for item in records:

            user, user_id, home_dir = item.split(' ')

            # print(user_id)

            if (not os.path.isdir(home_dir)):

                dir_no_exist.append([user, home_dir])

                continue

            attrs = os.stat(home_dir)

            uid = str(attrs.st_uid)

            if (uid != user_id):

                error_l.append([user, home_dir])


    if (len(error_l) != 0 or len(dir_no_exist) != 0):

        # error_l = [] # username, home_dir
        # dir_no_exist = [] # username, home_dir

        fail_l.append('(6.2.9) Ensure users own their home directories')

        msg = ''

        # if (len(dir_no_exist) != 0):

        #     msg += '\n' + color_symbol_debug() + text_color_yellow(' Run the following commands to create home dir for users: \n\n')

        #     for record in dir_no_exist:
        #         msg += "\t  " + text_color_orange('mkdir -p %s\n' % (record[1]))

        if (len(error_l) != 0):

            # def remove_duplicates_from_multi_list(input_l=[], keyword_index=0, compare_value=False, partial_match=False):
            # error_l = remove_duplicates_from_multi_list(error_l)

            msg += '\n' + color_symbol_debug() + text_color_yellow(' Run the following commands to correct ownership of users: \n\n')

            for info in error_l:
                msg += "\t  " + text_color_orange('sudo chown -R %s:%s %s\n' % (info[0], info[0], info[1]))

            remediation_msg_l.append(msg)

    else:

        pass_l.append('(6.2.9) Ensure users own their home directories')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ################################################################################
    #        6.2.10 Ensure users dot files are not group or world writable        #
    ################################################################################

    dir_l = get_dirs_in_path("/home")

    error_l = []

    # print(dir_l)
    # sys.exit()

    for home_dir in dir_l:

        fl = get_dot_files_in_dir(home_dir)

        for f in fl:

            try:
                attrs = os.stat(f)
            except FileNotFoundError:
                continue

            perm = oct(attrs.st_mode)
            group_perm = int(perm[-2])
            other_perm = int(perm[-1])

            if (group_perm > 5 or other_perm > 5):
                error_l.append(f)

    if (len(error_l) != 0):

        fail_l.append('(6.2.10) Ensure users dot files are not group or world writable')

        msg = ''

        if (len(error_l) != 0):

            msg += '\n' + color_symbol_debug() + text_color_yellow(' Run the following commands to correct permissions for dot files: \n\n')

            for fp in error_l:
                msg += "\t  " + text_color_orange('sudo chmod 700 %s\n' % (fp))

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(6.2.10) Ensure users dot files are not group or world writable')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ################################################################################
    #                 6.2.11 Ensure no users have .forward files                   #
    ################################################################################

    dir_l = get_dirs_in_path("/home")

    error_l = []

    # print(dir_l)
    # sys.exit()

    for home_dir in dir_l:

        fl = get_dot_files_in_dir(home_dir)

        for f in fl:

            if (os.path.basename(f) == '.forward'):
                error_l.append(f)

    if (len(error_l) != 0):

        fail_l.append('(6.2.11) Ensure no users have .forward files')

        msg = ''

        if (len(error_l) != 0):

            msg += '\n' + color_symbol_debug() + text_color_yellow(' Run the following commands to remove .forward files (they pose security risk): \n\n')

            for fp in error_l:
                msg += "\t  " + text_color_orange('sudo rm -rf %s\n' % (fp))

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(6.2.11) Ensure no users have .forward files')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ################################################################################
    #                   6.2.12 Ensure no users have .netrc files                   #
    ################################################################################

    dir_l = get_dirs_in_path("/home")

    error_l = []

    # print(dir_l)
    # sys.exit()

    for home_dir in dir_l:

        fl = get_dot_files_in_dir(home_dir)

        for f in fl:

            if (os.path.basename(f) == '.netrc'):
                error_l.append(f)

    if (len(error_l) != 0):

        fail_l.append('(6.2.12) Ensure no users have .netrc files')

        msg = ''

        if (len(error_l) != 0):

            msg += '\n' + color_symbol_debug() + text_color_yellow(' Run the following commands to remove .netrc files (leaks critical login information): \n\n')

            for fp in error_l:
                msg += "\t  " + text_color_orange('sudo rm -rf %s\n' % (fp))

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(6.2.12) Ensure no users have .netrc files')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ################################################################################
    #      6.2.13 Ensure users' .netrc Files are not group or world accessible     #
    ################################################################################

    dir_l = get_dirs_in_path("/home")

    error_l = []

    # print(dir_l)
    # sys.exit()

    for home_dir in dir_l:

        fl = get_dot_files_in_dir(home_dir)

        for f in fl:

            if (os.path.basename(f) != '.netrc'):
                continue

            try:
                attrs = os.stat(f)
            except FileNotFoundError:
                continue

            perm = oct(attrs.st_mode)
            group_perm = int(perm[-2])
            other_perm = int(perm[-1])

            if (group_perm > 0 or other_perm > 0):
                error_l.append(f)

    if (len(error_l) != 0):

        fail_l.append('(6.2.13) Ensure users .netrc files are not group or world writable')

        msg = ''

        if (len(error_l) != 0):

            msg += '\n' + color_symbol_debug() + text_color_yellow(' If you need to keep .netrc files, run the following commands to correct permissions: \n\n')

            for fp in error_l:
                msg += "\t  " + text_color_orange('sudo chmod 700 %s\n' % (fp))

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(6.2.13) Ensure users .netrc files are not group or world writable')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ################################################################################
    #                   6.2.14 Ensure no users have .rhosts files                  #
    ################################################################################

    dir_l = get_dirs_in_path("/home")

    error_l = []

    # print(dir_l)
    # sys.exit()

    for home_dir in dir_l:

        fl = get_dot_files_in_dir(home_dir)

        for f in fl:

            if (os.path.basename(f) == '.rhosts'):
                error_l.append(f)

    if (len(error_l) != 0):

        fail_l.append('(6.2.14) Ensure no users have .rhosts files')

        msg = ''

        if (len(error_l) != 0):

            msg += '\n' + color_symbol_debug() + text_color_yellow(' Run the following commands to remove .rhosts files (leaks critical login information): \n\n')

            for fp in error_l:
                msg += "\t  " + text_color_orange('sudo rm -rf %s\n' % (fp))

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(6.2.14) Ensure no users have .rhosts files')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ################################################################################
    #          6.2.15 Ensure all groups in /etc/passwd exist in /etc/group         #
    ################################################################################

    ## Groups are no longer defined in /etc/passwd in newer versions of linux, 
    ##  all group info is stored in /etc/group so there doesn't appear to be 
    ##   any major side effects if a user doesn't exist but is listed as part of
    ##    that group. Therefore we're skipping this check at this time.

    """
    dir_l = get_dirs_in_path("/home")

    error_l = []

    # print(dir_l)
    # sys.exit()

    for home_dir in dir_l:

        fl = get_dot_files_in_dir(home_dir)

        for f in fl:

            if (os.path.basename(f) == '.rhosts'):
                error_l.append(f)

    if (len(error_l) != 0):

        fail_l.append('(6.2.15) Ensure all groups in /etc/passwd exist in /etc/group')

        msg = ''

        if (len(error_l) != 0):

            msg += '\n' + color_symbol_debug() + text_color_yellow(' Run the following commands to remove .rhosts files (leaks critical login information): \n\n')

            for fp in error_l:
                msg += "\t  " + text_color_orange('sudo rm -rf %s\n' % (fp))

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(6.2.15) Ensure all groups in /etc/passwd exist in /etc/group')
    """


    ################################################################################
    #                    6.2.16 Ensure no duplicate UIDs exist                     #
    ################################################################################

    cmd = "cat /etc/passwd  | awk -F: {'print $3'} | sort | uniq -d"

    stdout, stderr, rc = run_cmd(cmd)

    test_failed = False

    dup_uid_l = []

    error_l = []

    if (stdout.strip() != ''):
        dup_uid_l = stdout.split('\n')

    # print(dup_uid_l)
    # sys.exit()

    for uid in dup_uid_l:
        cmd = "cat /etc/passwd  | awk -F: {'if ($3 == '%s') print $1'}" % uid
        stdout, stderr, rc = run_cmd(cmd)

        if (stdout.strip() != ''):
            users = stdout.split('\n')

            error_l.append([uid, users])

    # print(error_l)
    # sys.exit()

    if (len(error_l) != 0):

        fail_l.append('(6.2.16) Ensure no duplicate UIDs exist')

        msg = ''

        if (len(error_l) != 0):

            msg += '\n' + color_symbol_debug() + text_color_yellow(' The following users have the same UID in /etc/passwd: \n\n')

            for record in error_l:
                msg += "\t  " + text_color_green('%s %s\n' % (record[0], convert_list_to_str(record[1])))

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(6.2.16) Ensure no duplicate UIDs exist')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ################################################################################
    #                    6.2.17 Ensure no duplicate GIDs exist                     #
    ################################################################################

    cmd = "cat /etc/group | awk -F: {'print $3'} | sort | uniq -d"

    stdout, stderr, rc = run_cmd(cmd)

    test_failed = False

    dup_uid_l = []

    error_l = []

    if (stdout.strip() != ''):
        dup_uid_l = stdout.split('\n')

    # print(dup_uid_l)
    # sys.exit()

    for uid in dup_uid_l:
        cmd = "cat /etc/group  | awk -F: {'if ($3 == '%s') print $1'}" % uid
        stdout, stderr, rc = run_cmd(cmd)

        if (stdout.strip() != ''):
            users = stdout.split('\n')

            error_l.append([uid, users])

    # print(error_l)
    # sys.exit()

    if (len(error_l) != 0):

        fail_l.append('6.2.17 Ensure no duplicate GIDs exist')

        msg = ''

        if (len(error_l) != 0):

            msg += '\n' + color_symbol_debug() + text_color_yellow(' The following users have the same GID in /etc/group: \n\n')

            for record in error_l:
                msg += "\t  " + text_color_green('%s %s\n' % (record[0], convert_list_to_str(record[1])))

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(6.2.17) Ensure no duplicate GIDs exist')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ################################################################################
    #                 6.2.18 Ensure no duplicate user names exist                  #
    ################################################################################

    cmd = "cat /etc/passwd | awk -F: {'print $1'} | sort | uniq -d"

    stdout, stderr, rc = run_cmd(cmd)

    test_failed = False

    error_l = []

    if (stdout.strip() != ''):
        error_l = stdout.split('\n')

    if (len(error_l) != 0):

        fail_l.append('6.2.18 Ensure no duplicate user names exist')

        msg = ''

        if (len(error_l) != 0):

            msg += '\n' + color_symbol_debug() + text_color_yellow(' Duplicate username found in /etc/passwd: \n\n')

            for record in error_l:
                msg += "\t  " + text_color_green('%s\n' % record)

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(6.2.18) Ensure no duplicate user names exist')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ################################################################################
    #                 6.2.19 Ensure no duplicate group names exist                 #
    ################################################################################

    cmd = "cat /etc/group | awk -F: {'print $1'} | sort | uniq -d"

    stdout, stderr, rc = run_cmd(cmd)

    test_failed = False

    error_l = []

    if (stdout.strip() != ''):
        error_l = stdout.split('\n')

    if (len(error_l) != 0):

        fail_l.append('6.2.19 Ensure no duplicate group names exist')

        msg = ''

        if (len(error_l) != 0):

            msg += '\n' + color_symbol_debug() + text_color_yellow(' Duplicate group name found in /etc/group: \n\n')

            for record in error_l:
                msg += "\t  " + text_color_green('%s\n' % record)

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(6.2.19) Ensure no duplicate group names exist')

    progress_bar_obj.increment_count(1)
    progress_bar_obj.print()

    ################################################################################
    #                     6.2.20 Ensure shadow group is empty                      #
    ################################################################################

    cmd = "cat /etc/group | awk -F: {'if ($1 == \"shadow\") print $4'}"

    stdout, stderr, rc = run_cmd(cmd)

    test_failed = False

    error_l = []

    if (stdout.strip() != ''):
        error_l = stdout.split('\n')

    if (len(error_l) != 0):

        fail_l.append('6.2.20 Ensure shadow group is empty')

        msg = ''

        if (len(error_l) != 0):

            msg += '\n' + color_symbol_debug() + text_color_yellow(' The following users found in shadow group (/etc/group), which allows read access to /etc/shadow file: \n\n')

            for record in error_l:
                msg += "\t  " + text_color_green('%s\n' % record)

        remediation_msg_l.append(msg)

    else:

        pass_l.append('(6.2.20) Ensure shadow group is empty')

    progress_bar_obj.end_progress()
    clear_screen()
    print_header()

    ###########################################################################
    #                            CIS Report Generation                        #
    ###########################################################################

    fn = 'cis_report_%s.txt' % (datetime.today().strftime("%m-%d-%Y-%H-%M"))

    print_stats(pass_l, fail_l, True, fn)

    if (len(flags_inactive) != 0):
        print_sysctl_remediation(flags_inactive)

    #if (ssh_config_fails):
    #    remediation_msg_l.append(ssh_config_remediation)

    if (pam_config_fails):
        remediation_msg_l.append(pam_config_remediation)

    if (len(remediation_msg_l) != 0):

        for line in remediation_msg_l:
            print(line)

    if (len(perm_remediation_l) > 1):

        for line in perm_remediation_l:
            print(line)

    if (len(owner_remediation_l) > 1):

        for line in owner_remediation_l:
            print(line)

    if (len(perm_remediation_l) > 1 or len(perm_remediation_l) > 1):
        print_block(2)


def get_dirs_in_path(path=''):

    l = os.listdir(path)

    dir_l = []

    for d in l:

        dir_path = os.path.join(path, d) 

        if(os.path.isdir(dir_path)):
            dir_l.append(dir_path)

    return dir_l


def get_dot_files_in_dir(path=''):

    fl = []

    l = os.listdir(path)

    for f in l:

        fp = os.path.join(path, f)

        if (os.path.isfile(fp) and not os.path.islink(fp)):

            if (os.path.basename(fp).startswith('.')):

                fl.append(fp)

    return fl


# def get_dot_files_in_dir(path=''):

#     cmd = "ls -la %s | awk {'print $9'} | grep -E '^\.'" % (path)

#     stdout, stderr, rc = run_cmd(cmd)

#     fl = []

#     if (stdout.strip() != ''):
#         fl = stdout.split('\n')

#     _fl = []

#     for f in fl:

#         if (f == '.' or f == '..'):
#             pass
#         else:
#             _fl.append(f)

#     return _fl


def get_home_dir_l(path=''):

    cmd = "ls -la %s | awk {'print $9'}" % (path)

    stdout, stderr, rc = run_cmd(cmd)

    if (stdout.strip() != ''):
        fl = stdout.split('\n')

    _fl = []

    for f in fl:

        if (f == '.' or f == '..'):
            pass
        else:
            _fl.append(os.path.join(path, f))

    return _fl


def check_if_module_loaded(module_name=''):

    cmd = 'lsmod | grep "%s"' % module_name

    stdout, stderr, rc = run_cmd(cmd)

    if (rc == 0):
        return [True, remove_whitespace_special(stdout.splitlines())]
    else:
        return [False, []]


def check_if_support_for_module_enabled(module_name=''):

    cmd = 'modprobe -n -v "%s"' % module_name

    stdout, stderr, rc = run_cmd(cmd)

    if (rc == 0):
        return [True, remove_whitespace_special(stdout.splitlines())]
    else:
        return [False, []]


def print_stats(pass_l=[], fail_l=[], generate_report=False, report_name='Report.txt'):

    print_l = []

    lines = '  ' + '\u2501' * 71
    # print(lines)
    # print()
    print_l.append('\n')

    total_controls = len(pass_l) + len(fail_l)
    percent = 0.0

    try:
        percent = (len(pass_l) / total_controls) * 100
    except (ZeroDivisionError):
        pass

    msg = ''

    report_msg = ''

    if (percent == 0 and len(fail_l) == 0 and len(pass_l) == 0):
        msg = '  ' + color_pair_error()+ 'No Tests Loaded' + color_reset()
        print(msg)
        sys.exit(1)
    elif (percent < 60):
        report_msg += '  FAIL: '
        msg = '  ' + color_pair_error() + 'FAIL:' + color_reset() + ' '

        msg += '(%d/%d) %.2f%%' % (len(pass_l), total_controls, percent)
        report_msg += '(%d/%d) %.2f%%' % (len(pass_l), total_controls, percent)
    else:
        report_msg += '  PASS'
        txt = text_color_green('PASS')
        msg = '  ' + txt

        msg += '  (%d/%d) %.2f%%' % (len(pass_l), total_controls, percent)
        report_msg += '  (%d/%d) %.2f%%' % (len(pass_l), total_controls, percent)


    print(msg)
    print_l.append(report_msg)

    if (len(pass_l) != 0):
        print()
        print(lines)
        print()


    for c in pass_l:
        text = '%s' % c
        print(color_symbol_info() + ' ' + text)

    if (len(fail_l) != 0):
        print()
        print(lines)
        print()
        print_l.append(lines)

    for c in fail_l:
        text = '%s' % c
        print('  ' + color_symbol_error() + ' ' + text)
        print_l.append('  ' + text)

    if (not (len(pass_l) == 0 and len(fail_l) == 0)):
        print()
        print(lines)
        print()
        print_l.append(lines)

    if (generate_report):
        write_list_to_file(print_l, report_name)


#===========================================================================
#                               File IO Functions                          #
#===========================================================================

def check_if_files_are_valid(fl=[], fp=[]):

    output_valid = []
    output_invalid = []

    for f in fl:

        found = False

        for path in fp:

            new_fp = os.path.join(path, f)

            if (os.path.isfile(new_fp)):
                found = True
                output_valid.append(new_fp)
                break

        if (found == False): # We couldn't find a file so seeking for all invalid ones
            output_invalid.append(f)

    return (output_valid, output_invalid)


# [x] Tested
def search_for_file(path='', fn='', search_all=False):

    if (fn == ''):
        return (False, [])
    elif (path != '' and not os.path.isdir(path)):
        return (False, [])

    cmd = ''

    if (search_all):
        if (path == ''):
            cmd = 'find . -type f -iname "*%s*"' % fn
        else:
            cmd = 'find %s -type f -iname "*%s*"' % (path, fn)
    else:
        if (path == ''):
            cmd = 'find . -type f -iname "%s"' % fn
        else:
            cmd = 'find %s -type f -iname "%s"' % (path, fn)

    stdout, stderr, rc = run_cmd(cmd)

    if (rc != 0):
        return (False, [])
        
    fl = stdout.strip().split('\n')

    fl = remove_all_elements_from_list(fl, [''])

    if (len(fl) == 0):
        return (False, [])
    else:

        _fl = []

        for f in fl:
            if (f.strip() != ''):
                _fl.append(f.strip())

        return (True, _fl)


# [x] Tested
def read_from_file(fp='', lines_to_skip=[]):

    if (not os.path.isfile(fp)):
        return (False, [])

    data = []

    try:

        with open(fp, 'r') as fh:
            data = fh.read().strip().splitlines()

    except (IOError, BaseException) as e:
        #print('Error occured')
        #print(e)
        return (False, [])

    data = remove_all_elements_from_list(data, lines_to_skip)

    return (True, data)


# [x] Tested
def write_list_to_file(l=[], fn=''):

    if (len(l) == 0 or fn == ''):
        return False

    try:

        with open(fn, 'w') as fh:

            for item in l:
                _item = '%s\n' % item
                fh.writelines(_item)

    except (IOError, BaseException) as e:
        #print('Error occured')
        #print(e)
        return False

    return True


# [x] Tested
def write_str_to_file(s='', fn=''):

    if (len(s) == 0 or fn == ''):
        return False

    try:

        with open(fn, 'w') as fh:
            fh.write(s)

    except (IOError, BaseException) as e:
        #print('Error occured')
        #print(e)
        return False

    return True


#===========================================================================
#                             Utility Functions                            #
#===========================================================================


def get_list_of_all_users():

    cmd = "sudo cat /etc/shadow | cut -d':' -f1" 

    stdout, stderr, rc = run_cmd(cmd)

    user_l = []

    if (rc == 0): 

        user_l = remove_all_elements_from_list(stdout.splitlines(), ['','\n'])

        user_l = remove_whitespace_from_list(user_l)

    return user_l


def compare_with_date(day1=1, month1=1, year1=1990, day2=2, month2=2, year2=1990):

    """
    Returns the number of days difference between 2 dates

    """
    
    date1 = date(year1, month1, day1)
    date2 = date(year2, month2, day2)
    num_days = date2 - date1

    return num_days.days
                

def convert_month_str_to_int(m='Jan'):

    months = { 'jan': 1, 'feb': 2, 'mar': 3, 'apr':4, 'may':5, 'jun':6, 'jul':7, \
            'aug':8, 'sep':9, 'oct':10, 'nov':11, 'dec':12 }

    return months.get(m.lower())


# [x] Tested
def search_in_2d_list(l=[], keyword='', keyword_type_str=False,
        keyword_type_int=False, keyword_index=0, compare_value=False,
        value_index=1, value=-1, convert_to_int=False, partial_match=True):

    if (keyword_type_int):

        if (compare_value):

            for i in range(0, len(l)):

                _val = l[i][value_index]

                conversion_success = True

                if (convert_to_int):

                    output = convert_str_to_int(_val)

                    if (output[0]):
                        _val = output[1][0]
                    else:
                        conversion_success = False

                if (partial_match and conversion_success):
                    if (l[i][keyword_index].find(keyword) >= 0 and _val == value):
                        return (True, i)
                elif (partial_math == False and conversion_success):
                    if (l[i][keyword_index] == keyword and _val == value):
                        return (True, i)
        else:

            for i in range(0, len(l)):

                if (partial_match):
                    if (l[i][keyword_index].find(keyword) >= 0):
                        return (True, i)
                else:
                    if (l[i][keyword_index] == keyword):
                        return (True, i)


    elif (keyword_type_str):

        if (compare_value):

            for i in range(0, len(l)):

                if (partial_match):

                    if (l[i][keyword_index].find(keyword) >= 0 and l[i][value_index] == value):
                        return (True, i)
                    
                else:

                    if (l[i][keyword_index] == keyword and l[i][value_index] == value):
                        return (True, i)

        else:

            for i in range(0, len(l)):

                if (partial_match):

                    if (l[i][keyword_index].find(keyword) >= 0):
                        return (True, i)
                    
                else:

                    if (l[i][keyword_index] == keyword):
                        return (True, i)

    return (False, -1)


# [x] Tested
def remove_duplicates_from_2d_list(l=[], keyword_index=0, compare_value=False, partial_match=False):

    _l = []

    for i in range(0, len(l)):

        kw = l[i][keyword_index]

        output = search_in_2d_list(_l, kw, keyword_type_str=True, keyword_index=keyword_index)

        if (not output[0]):
            _l.append(l[i])
            
    return _l


def validate_line_in_config_with_variable_params(line='', params=[], \
        fixed_param_indexes=[], delimiter='', fail_if_extra_param=False, trim_whitespace=True):

    """
    delimiter == '' : Splits line parameters based on whitespace

    fixed_param_indexes : Indexes from arg 'params' will maintain their order in the line

    Returned codes:

    0 = success,
    1 = extra params,
    2 = missing params,
    3 = order of params incorrect
    """
    
    l = []

    if (delimiter == ''):
        l = line.split()
    else:
        l = line.split(delimiter)

    if (trim_whitespace):

        for i in range(len(l)):

            l[i] = l[i].strip()

    # Extra params
    if (fail_if_extra_param):

        extra_params = []

        for item in l:
            if (item not in params):
                extra_params.append(item)

        if (len(extra_params) != 0):
            return (1, extra_params)

    # Missing params
    missing_params = []

    for item in params:

        try:
            l.index(item)
        except ValueError:
            missing_params.append(item)

    if (len(missing_params) != 0):
        return (2, missing_params)
    
    # Checking for order of params
    if (len(fixed_param_indexes) != 0):

        invalid_order_l = []

        for index in fixed_param_indexes:

            if (params[index] != l[index]):
                invalid_order_l.append(params[index])

        if (len(invalid_order_l) != 0):
            return (3, invalid_order_l)

    return (0, [])


# [x] Tested
def get_file_permission(fp=''):

    attrs = os.stat(fp)
    perm = oct(attrs.st_mode)
    user_perm = int(perm[-3])
    group_perm = int(perm[-2])
    other_perm = int(perm[-1])

    return user_perm, group_perm, other_perm


# [x] Tested
def check_if_user_root():

    if (os.geteuid() == 0):
        return True

    return False


# [x] Tested
def run_cmd(cmd='', verbose=False):
    """
    Exec local bash cmds
    """

    if (type(cmd) == str):
        process = subprocess.Popen(cmd, shell=True, \
                stdout=subprocess.PIPE, \
                stderr=subprocess.PIPE)

        stdout, stderr = process.communicate()

        stdout = stdout.decode('utf-8').strip()
        stderr = stderr.decode('utf-8').strip()

        if (verbose):
            print(stdout)

        return stdout, stderr, process.returncode

    else:

        return '', '', ''


# [x] Tested
def audit_pw_complexity(pw=''):
    """
    Using the most secure pw check (as per senior staff recommendation)

    - Combination of upper & lower characters need to be present
    - Atleast 1 numeric character
    - Min password length of 10
    """

    if (pw == ''):
        return False
    elif (len(pw) < 10):
        return False
    else:

        lw_case = False
        up_case = False
        numeric = False

        for c in pw:
            c_int = ord(c)
            if (c_int >= 97 and c_int <= 122):
                lw_case = True
                break

        for c in pw:
            c_int = ord(c)
            if (c_int >= 65 and c_int <= 90):
                up_case = True
                break
        
        for c in pw:
            c_int = ord(c)
            if (c_int >= 48 and c_int <= 67):
                numeric = True
                break

        if (lw_case and up_case and numeric):
            return True
        else:
            return False


# [x] Tested
def prompt_yes_no(question="", default=True):
    """
    Asks yes/no & returns a boolean value.
    """

    choice_list = ['y', 'yes', 'yesh', 'n', 'no', 'nou']

    try:
        while (True):
            choice = prompt_blank(question)

            if (choice in choice_list):
                if (choice in choice_list[:3]):
                    return True
                else:
                    return False
            elif (choice == ''):
                return default
            else:
                print(text_error("Invalid answer.  Please answer 'yes/no'"))
    except KeyboardInterrupt:
        sys.exit(1)


# [x] Tested
def remove_whitespace(s=''):

    _s = ''

    for i in range(len(s)):
        if (s[i] != ' '):
            _s += s[i]

    return _s


# [x] Tested
def remove_whitespace_special(s=''):

    if (len(s) == 0):

        return s

    elif (type(s) == str):

        return ' '.join(s.strip().split())

    elif (type(s) == list):

        _s = []

        for item in s:

            _s.append(' '.join(item.strip().split()))

        return _s

    else:
        return s


# [x] Tested
def remove_whitespace_from_list(l=[], remove_all_whitespace=False):

    _l = []

    for item in l:

        if (remove_all_whitespace):
            _l.append(remove_whitespace(item))

        else:
            _l.append(item.strip())

    return _l


# [x] Tested
def convert_list_to_str(l=[], delimiter=' '):

    s = ''

    for item in l:
        s += '%s%s' % (item, delimiter)
        
    s = s.strip()

    if (delimiter == ',' or ', '):

        if (s.endswith(',')):
            s = s[:-1].strip()
            
    return s


# [x] Tested
def convert_str_to_int(val=''):

    _val = parse_comma(val)

    try:
        for i in range(len(_val)):

            _val[i] = int(_val[i])
            
    except ValueError:
        
        return (False, [])

    return (True, _val)


def count_char(s='', char=''):

    if (char in s):

        count = 0

        for i in s:
            if (i == char):
                count += 1

        return count
    else:
        return 0


# [x] Tested
def check_if_index_is_valid(index_l=[], start_range=0, end_range=0):
    """
    start & end ranges are exclusive
    """

    for index in index_l:

        if (not (index >= start_range and index <= end_range)):
            return False

    return True


# [x] Tested
def search_element_in_list(l=[], keyword='', ignore_case=False):

    key = ''

    if (ignore_case):

        key = keyword.lower()

        for item in l:

            if (key in item.lower()):
                return (True, item)
    else:

        key = keyword

        for item in l:

            if (key in item):
                return (True, item)

    return (False, [])


def check_if_all_element_in_list(input_l=[], check_l=[], ignore_case=False):

    result = True

    output_l = []

    if (ignore_case):

        for item in check_l:

            if (item.lower() in input_l):
                continue
            else:
                result = False
                output_l.append(item)

    else:

        for item in check_l:

            if (item in input_l):
                continue
            else:
                result = False
                output_l.append(item)

    if (result):
        return (True, [])
    else:
        return (False, output_l)


# [x] Tested
def remove_all_elements_from_list(l=[], element_l=[], 
        starts_with_l=[], ends_with_l=[]):

    _l = l

    for item in element_l:
        _l = [x for x in _l if x != item]
    
    for item in starts_with_l:
        _l = [x for x in _l if x.startswith(item) != True]

    for item in ends_with_l:
        _l = [x for x in _l if x.endswith(item) != True]

    return _l


# [x] Tested
def parse_comma(val=""):

    if (type(val) != str):
        return val

    data = val.strip().split(',')

    return data


# [x] Tested
def check_if_quoted(s=''):

    l = []

    if ("'" in s):
        l.append("'")

    if ('"' in s):
        l.append('"')

    if (len(l) == 0):
        return (False, l)
    else:
        return (True, l)


# [x] Tested
def remove_char_from_str(s='', c=''):

    return ''.join([x for x in s if x != c])


# [x] Tested
def remove_quote_from_str(s=""):

    output = check_if_quoted(s) 

    if (output[0] == False):
        return s
    else: 

        _s = s

        if ("'" in output[1]):
            _s = remove_char_from_str(_s, "'")

        if ('"' in output[1]):
            _s = remove_char_from_str(_s, '"')

        return _s


def check_if_ip_valid(s=''):

    """
    Basic check, not really checking if it is a valid ip address
    """

    if('.' in s):

        if (count_char(s, '.') == 3):

            _s = remove_whitespace(s).split('.')

            if (len(_s) != 4):
                return False

            for unit in _s:

                output = convert_str_to_int(unit)

                if (output[0] and output[1][0] <= 255):
                    continue
                else:
                    return False

            return True

    return False


def validate_pkg_mgrs():

    global pkgmgr_installed, pkgmgr_rpm, pkgmgr_dpkg

    output = search_for_file('/usr/bin/', 'rpm')

    if (output[0]):
        pkgmgr_rpm = True

    output = search_for_file('/usr/bin/', 'dpkg')

    if (output[0]):
        pkgmgr_dpkg = True

    if (pkgmgr_rpm or pkgmgr_dpkg):
        pkgmgr_installed = True


# [ ] Needs testing
def pkgmgr_search_if_installed(app_name=''):

    global pkgmgr_installed, pkgmgr_rpm, pkgmgr_dpkg

    if (pkgmgr_installed):

        cmd = ''

        if (pkgmgr_dpkg):
            cmd = 'sudo dpkg -s %s' % app_name
        elif (pkgmgr_rpm):
            cmd = 'sudo rpm -q %s' % app_name

        stdout, stderr, rc = run_cmd(cmd) 

        if (rc == 0): 
            return True

    # Doing manual search, even if pkgmgr doesn't find anything

    paths = ['/usr/bin/', '/usr/sbin/', '/bin/', '/sbin/']
    output = check_if_files_are_valid([app_name], paths) 

    if (len(output[1]) != 0):
        return False
    else:
        return True
    

def pkgmgr_print_install_cmd(app_name=''):

    global pkgmgr_installed, pkgmgr_rpm, pkgmgr_dpkg

    cmd = ''

    if (pkgmgr_dpkg):
        cmd = 'sudo dpkg -i %s' % app_name
    elif (pkgmgr_rpm):
        cmd = 'sudo rpm -i %s' % app_name
    else:
        cmd = '<pkgmgr> install %s' % app_name

    return cmd


def pkgmgr_print_uninstall_cmd(app_name=''):

    global pkgmgr_installed, pkgmgr_rpm, pkgmgr_dpkg

    cmd = ''

    if (pkgmgr_dpkg):
        cmd = 'sudo dpkg -r %s' % app_name
    elif (pkgmgr_rpm):
        cmd = 'sudo rpm -e %s' % app_name
    else:
        cmd = 'sudo <pkgmgr> remove %s' % app_name

    return cmd


def get_sysctl_configs_system():

    sysctl_fl = []

    if (os.path.isfile('/etc/sysctl.conf')):
        sysctl_fl.append('/etc/sysctl.conf')

    output = search_for_file('/etc/sysctl.d/', '*.conf')

    if (output[0]):
        sysctl_fl = sysctl_fl + output[1]

    configs = []

    for f in sysctl_fl:
        
        data = read_from_file(f, ['','#','\n'])
    
        if (data[0]):
            _data = remove_all_elements_from_list(data[1], starts_with_l=['#'])
            configs += _data

    for i in range(len(configs)):
        tmp = configs[i]
        configs[i] = remove_whitespace(tmp)

    return configs


# [x] Tested
def get_sysctl_config_validator(fp=''):

    configs = []

    if (os.path.isfile(fp)):

       data = read_from_file(fp, ['','#','\n',' '])
       
       if (data[0]):

           _data = remove_all_elements_from_list(data[1], starts_with_l=['#', ' '])

           # configs = [CIS#, Desc, [sysctl flags]]

           for item in _data:
               # tmp = [sysctl flag, CIS#, Desc]
               tmp = item.split(',')
                
               # Removin space which might mess with detection
               flag = remove_whitespace(tmp[0].strip())
               cis_num = remove_whitespace(tmp[1].strip())
               desc = tmp[2].strip()

               found = False

               for j in range(len(configs)):

                   if (cis_num == configs[j][0]):
                       configs[j][2].append(flag)
                       found = True
                       break
                
               if (not found):
                   configs.append([cis_num,desc,[flag]])

    return configs


# def validate_config_parameters(config=[], validator=[]):

#     """
#     Assuming for validator is a 2D lists, & config is a list of strings.
#         Any items in the list can appear in any order in the string 
#     """

#     for i in range(len(validator)):

#         val_l = validator[i]

#         found = False

#         for j in range(len(val_l)):

#             val_item = val_l[j]

#             for k in range(len(config)):

#                 config_s = config[k]

#                 if (config_s.find(val_item))

#             if (output):
#                 found = True
#                 break

#         if (not found):
#             return False

#     return True



#===========================================================================
#                      User input parsing functions                        #
#===========================================================================

# [x] Tested
def get_user_choice_from_options(l=[], msg='', multiple_options=False):

    """
    Input params:
        l                : List of available options
        msg              : Custom message
        multiple_options : Decide whether to allow multi option
    """

    if (len(l) == 0):
        return (False, [])

    _msg = msg

    if (msg == ''):
        _msg = 'Available Options: '

    print(text_debug(_msg))

    for u in range(len(l)):
        print(text_highlight('\t%d) ' % (u+1) + l[u]))

    while (True):

        try:

            output = ''

            print()

            val = prompt('     >  ', simple=True)

            if (',' not in val):

                output = convert_str_to_int(val)

                if (output[0]):

                    if (check_if_index_is_valid(output[1], 1, len(l))):
                        return (True, [x-1 for x in output[1]])
                    else:
                        print('\n' + text_error('Selected option is not valid, try again'))
                        continue
                else:
                    print('\n' + text_error('Requires an integer, try again'))
                    continue

            elif (',' in val and multiple_options == False):

                print('\n' + text_error('Multiple options are not allowed'))
                continue

            elif (',' in val and multiple_options):
                output = convert_str_to_int(val)

                if (output[0]):
                    
                    if (check_if_index_is_valid(output[1], 1, len(l))):
                        return (True, [x-1 for x in output[1]])
                    else:
                        print('\n' + text_error('Selected option is not valid'))
                        continue
            else:
                print('\n' + text_error('Selected option is not valid'))
                continue


        except KeyboardInterrupt:
            return (False, [])

    return (False, [])


def prompt(question="", ignore_case=True):

    value = ""

    while (value == ""):
        value = input(text_debug(question))

        if (value == ""):
            print(text_error("Field cannot be blank"))

    if (ignore_case):
        return value.lower()
    else:
        return value


def prompt_blank(question=""):

    value = input(color_symbol_prompt() + ' ' +  text_highlight(question))
    return value


def prompt_blank_fixed_width(question="", question_width=10, left_indent=2):

    symbol = '[+] '

    tl1 = list(' ' * (left_indent))
    tl2  = list(symbol)
    tl3 = list(' ' * (question_width))

    q_list = list(question)

    for i in range(len(q_list)):
        tl3[i] = q_list[i]

    text = ''.join(tl1) + color_b('cyan') + ''.join(tl2) + color_reset() + \
            text_highlight(''.join(tl3))

    value = input(text)

    return value


def prompt_yes_no(question="", default=True):
    """
    Asks yes/no & returns a boolean value.
    """

    choice_list = ['y', 'yes', 'yesh', 'n', 'no', 'nou']

    while (True):
        choice = prompt_blank(question)

        if (choice in choice_list):
            if (choice in choice_list[:3]):
                return True
            else:
                return False
        elif (choice == ''):
            return default
        else:
            print(text_error("Invalid answer.  Please answer 'yes/no'"))


def prompt_yes_no_blank(question=""):
    """
    Asks yes/no & returns a boolean value.
    """

    choice_list = ['y', 'yes', 'yesh', 'n', 'no', 'nou']

    while (True):
        choice = prompt_blank(question)

        if  (choice in choice_list):
            if (choice in choice_list[:3]):
                return True
            else:
                return False
        elif (choice == ''):
            return ''
        else:
            print(text_error("Invalid answer. Please answer 'yes/no' or leave blank"))


#===========================================================================
#                           Printing functions                             #
#===========================================================================

def print_help():

    print("""
        %s[-h, --help]%s

            Prints this output

        %s[-a, --audit]%s

            Run CIS audit 

        %s[-a, --audit] %s[network_config.txt]%s

            Run CIS audit with custom path for network config file

    """ % (color_b('orange'), color_reset(), \
            color_b('orange'), color_reset(), \
            color_b('orange'), color_b('yellow'), color_reset()))


def print_header():

    lines = '  ' + '\u2501' * 71

    print()
    print(lines)

    print(text_highlight("""%s\t\t\t      CIS Auditor%s v%s%s""" %(color_b('cyan'), color_b('green'), __version__, color_reset())))

    print(lines)
    print()


def print_list(l=[], cond=True):

    for item in l:

        msg = ''

        if (cond):
            msg = text_debug(item)
        else:
            msg = text_error(item)

        print(msg)


#===========================================================================
#                           Printing functions                             #
#===========================================================================

def clear_screen():

    """
    Clears screen, command is compatible with different OS
    """

    cmd = 'clear'

    os.system(cmd)


def cursor_hide():

    print("\033[?25l")


def cursor_show():

    print("\033[?25h")


def text_b():

    return "\x1B[1m"


def color_n(c=''):

    """
    Normal colors
    """

    if (c == 'white'):
        return "\x1B[0;37m"
    elif (c == 'blue'):
        return "\x1B[0;34m"
    elif (c == 'yellow'):
        return "\x1B[0;38;5;220m"
    elif (c == 'red'):
        return "\x1B[0;31m"
    elif (c == 'green'):
        return "\x1B[0;32m"
    elif (c == 'black'):
        return "\x1B[0;30m"
    else:
        return ""


def color_b(c=''):

    """
    Bold colors
    """

    if (c == 'white'):
        return '\x1B[1;38;5;15m'
    elif (c == 'blue'):
        return '\x1B[1;34m'
    elif (c == 'purple'):
        return '\x1B[1;38;5;141m'
    elif (c == 'cyan'):
        return '\x1B[1;38;5;51m'
    elif (c == 'yellow'):
        return '\x1B[1;33m'
    elif (c == 'light_yellow'):
        return '\x1B[1;38;5;229m'
    elif (c == 'orange'):
        return '\x1B[1;38;5;214m'
    elif (c == 'red'):
        return '\x1B[1;31m'
    elif (c == 'green'):
        return '\x1B[1;38;5;118m'
    elif (c == 'black'):
        return '\x1B[1;38;5;0m'
    else:
        return ""


def color_bg(c=''):

    """
    Background colors
    """

    if (c == 'reset'):
        return "\x1B[40m"
    elif (c == 'white'):
        return '\x1B[1;48;5;15m'
    elif (c == 'blue'):
        return '\x1B[1;44m'
    elif (c == 'purple'):
        return '\x1B[1;48;5;141m'
    elif (c == 'cyan'):
        return '\x1B[1;48;5;51m'
    elif (c == 'yellow'):
        return '\x1B[1;48;5;229m'
    elif (c == 'orange'):
        return '\x1B[1;48;5;214m'
    elif (c == 'red'):
        return '\x1B[1;41m'
    elif (c == 'green'):
        return '\x1B[1;48;5;118m'
    elif (c == 'black'):
        return '\x1B[1;48;5;0m'
    else:
        return ""


def color_pair(p=''):

    """
    Color pair combination

    parameter format: 
        foreground_background
            e.g: 'white_black'
    """

    if (p == 'white_blue'):
        s = '%s%s' % (color_b('white'), color_bg('blue'))
        return s
    elif (p == 'white_yellow'):
        s = '%s%s' % (color_b('white'), color_bg('yellow'))
        return s
    elif (p == 'white_red'):
        s = '%s%s' % (color_b('white'), color_bg('red'))
        return s
    elif (p == 'white_green'):
        s = '%s%s' % (color_b('white'), color_bg('green'))
        return s
    elif (p == 'white_black'):
        s = '%s%s' % (color_b('white'), color_bg('black'))
        return s
    elif (p == 'blue_white'):
        s = '%s%s' % (color_b('blue'), color_bg('white'))
        return s
    elif (p == 'blue_yellow'):
        s = '%s%s' % (color_b('black'), color_bg('yellow'))
        return s
    elif (p == 'blue_red'):
        s = '%s%s' % (color_b('black'), color_bg('red'))
        return s
    elif (p == 'blue_green'):
        s = '%s%s' % (color_b('black'), color_bg('green'))
        return s
    elif (p == 'blue_black'):
        s = '%s%s' % (color_b('blue'), color_bg('black'))
        return s
    elif (p == 'yellow_white'):
        s = '%s%s' % (color_b('yellow'), color_bg('white'))
        return s
    elif (p == 'yellow_blue'):
        s = '%s%s' % (color_b('yellow'), color_bg('blue'))
        return s
    elif (p == 'yellow_red'):
        s = '%s%s' % (color_b('yellow'), color_bg('red'))
        return s
    elif (p == 'yellow_green'):
        s = '%s%s' % (color_b('yellow'), color_bg('green'))
        return s
    elif (p == 'yellow_black'):
        s = '%s%s' % (color_b('yellow'), color_bg('black'))
        return s
    elif (p == 'red_white'):
        s = '%s%s' % (color_b('red'), color_bg('white'))
        return s
    elif (p == 'red_blue'):
        s = '%s%s' % (color_b('red'), color_bg('blue'))
        return s
    elif (p == 'red_yellow'):
        s = '%s%s' % (color_b('red'), color_bg('yellow'))
        return s
    elif (p == 'red_green'):
        s = '%s%s' % (color_b('red'), color_bg('green'))
        return s
    elif (p == 'red_black'):
        s = '%s%s' % (color_b('red'), color_bg('black'))
        return s
    elif (p == 'green_white'):
        s = '%s%s' % (color_b('green'), color_bg('white'))
        return s
    elif (p == 'green_blue'):
        s = '%s%s' % (color_b('green'), color_bg('blue'))
        return s
    elif (p == 'green_yellow'):
        s = '%s%s' % (color_b('green'), color_bg('yellow'))
        return s
    elif (p == 'green_red'):
        s = '%s%s' % (color_b('green'), color_bg('red'))
        return s
    elif (p == 'green_black'):
        s = '%s%s' % (color_b('green'), color_bg('black'))
        return s
    elif (p == 'black_white'):
        s = '%s%s' % (color_b('black'), color_bg('white'))
        return s
    elif (p == 'black_blue'):
        s = '%s%s' % (color_b('black'), color_bg('blue'))
        return s
    elif (p == 'black_yellow'):
        s = '%s%s' % (color_b('black'), color_bg('yellow'))
        return s
    elif (p == 'black_orange'):
        s = '%s%s' % (color_b('black'), color_bg('orange'))
        return s
    elif (p == 'black_red'):
        s = '%s%s' % (color_b('black'), color_bg('red'))
        return s
    elif (p == 'black_green'):
        s = '%s%s' % (color_b('black'), color_bg('green'))
        return s


def color_pair_error():
    return color_pair('red_black')


def color_reset():
    """
    Reset bg & fg colors
    """
    return "\x1B[0m"


def text_error(text=''):
    text = '\n' + '  ' + color_symbol_error() + \
            ' ' + text + ' ' + color_reset() + '\n'     
    return text


def text_color_cyan(text=''):
    text =  color_b('cyan') + text + color_reset()
    return text


def text_color_yellow(text=''):
    text =  color_b('yellow') + text + color_reset()
    return text


def text_color_orange(text=''):
    text =  color_b('orange') + text + color_reset()
    return text


def text_color_red(text='', padding = ''):
    text =  color_b('red') + text + color_reset()
    return text


def text_color_green(text='', padding = ''):
    text =  color_b('green') + text + color_reset()
    return text


def text_color_magenta(text='', padding = ''):
    text =  color_b('purple') + text + color_reset()
    return text


def text_highlight(text=''):
    text =  text_b() + text + color_reset()
    return text


def text_debug(text=''):
    text = color_symbol_debug() + " " + text_highlight(text)
    return text


def color_symbol_info():
    text = '  ' + color_b('cyan') + '[+]' + color_reset()
    return text


def color_symbol_question():
    text = '  ' + color_b('orange') + '[?]' + color_reset() 
    return text


def color_symbol_prompt():
    text = '  ' + color_b('green') + '[>]' + color_reset()
    return text


def color_symbol_error():
    text = color_b('red') + '[-]' + color_reset()
    return text


def color_symbol_debug():

    text = '  ' + color_b('blue') + '[*]' + color_reset()
    return text


def print_block(n=3):
    for i in range(n):
        print()


def print_sysctl_remediation(flags=[], indent='\t  '):

    msg = color_symbol_debug() + text_color_yellow(' Set the following parameters in /etc/sysctl.conf file: \n\n')

    for flag in flags:

        msg += text_color_green('%s%s\n' % (indent, flag))

    print(msg)


class ProgressBar():

    def __init__(self, count_init, count_total):

        self.__count_current = 0
        self.__count_total = 0

        if (count_init <= 0):
            self.__count_current = 0
        else:
            self.__count_current = count_init

        if (count_total < 0):
            self.__count_total = 10
        else:
            self.__count_total = count_total


    def increment_count(self, count):

        if (self.__count_current >= self.__count_total):
            self.__count_current = self.__count_total
        else:
            self.__count_current += count


    def end_progress(self):

        self.__count_current = self.__count_total
        self.print()
        sleep(2)
        cursor_show()


    def print(self):

        self.__update_progress_bar_classic(self.__count_current, self.__count_total)


    def __update_progress_bar_classic(self, index=1,index_range=10, \
            left_indent=25, right_indent=5): 

        """
        Classic progress bar

        Args:    1) This represents the amount completed out of the total amount
                 2) This represents the total amount
                 3) Amount of padding on the left
                 4) Amount of padding on the right

        Returns: None
        """

        color = color_pair('black_orange')

        bar_length = 20

        total_text = list(' ' * bar_length)

        center = int(len(total_text)/2)

        percentage_remaining = (index/index_range) * 100
        percentage_remaining = int(percentage_remaining)
        percentage_remaining_str = '%3d' % percentage_remaining

        if (index >= index_range-2):
           progress_text = ' '
           total_text[center-2] = '1'
           total_text[center-1] = '0'
           total_text[center] = '0'
           total_text[center+1] = '%'
           remaining_text = ''.join(total_text[:])

           new_text = color_reset() + ' ' * left_indent + color + color_b('black') + \
                   '[ ' + remaining_text + ' ]' + color_reset() + ' ' * right_indent
        else:

            total_text[center-2] = percentage_remaining_str[0]
            total_text[center-1] = percentage_remaining_str[1]
            total_text[center] = percentage_remaining_str[2]
            total_text[center+1] = '%'

            ratio = float(index/index_range * 1.0)
            progress_amount = int(bar_length * ratio)

            progress_text = ''.join(total_text[:progress_amount])
            remaining_text = ''.join(total_text[progress_amount:])

            color_dark_blue = color_b('white')

            if (progress_amount >= (center)):

                new_text = color_reset() + ' ' * left_indent + color + color_b('black') + \
                        '[ ' + color_b('black') + progress_text + color_bg('black') + remaining_text + \
                        color_dark_blue + ' ]' + color_reset() + ' ' * right_indent
            else:

                new_text = color_reset() + ' ' * left_indent + color + color_b('black') + \
                        '[ ' + color_dark_blue + progress_text + color_bg('black') + remaining_text + \
                        color_b('yellow') + ' ]' + color_reset() + ' ' * right_indent

        sys.stdout.write('\r')
        sys.stdout.write("%s" % new_text)
        sys.stdout.flush()


def progress_bar(time_wait=21):

    length = 50 * time_wait

    print()

    cursor_hide()

    percent_10_in_units = int(time_wait * 0.1)

    for i in range(length):

        if (i >= (length-percent_10_in_units)):
            break

        update_progress_bar_classic(i, length)
        sleep(0.022)

        if ((i%50 == 0) or (i%25 == 0) or (i%100 == 0)):
            sleep(0.10)


#===========================================================================
#                   Custom Exception Handling Classes                      #
#===========================================================================

class PkgMgrNotFoundException(Exception):
    def __init__(self, msg='No known package manager was found in system'):
        super(PkgMgrNotFoundException, self).__init__(msg)


def remove_duplicates_from_multi_list(input_l=[], keyword_index=0, compare_value=False, partial_match=False):

    """
    * Supports operation on str & int data types for multi dimensional list

    TODO: Use a better search to remove duplicates

    """

    discard_l = []
    index_l = []

    if (len(input_l) == 0):
        return input_l
    elif (type(input_l[0]) != list):
        raise Exception('remove_duplicates_from_2d_list(): 1st param (list) is not a 2d list')
    elif (keyword_index < 0 or keyword_index >= len(input_l[0])):
        raise Exception('remove_duplicates_from_2d_list(): 2nd param (keyword index) out of range')

    _keyword_type_str = False
    _keyword_type_int = False

    if (type(input_l[0][keyword_index]) == str):
        _keyword_type_str = True
    elif (type(input_l[0][keyword_index]) == int):
        _keyword_type_int = True
    else:
        raise Exception('remove_duplicates_from_2d_list(): only str and int are currently supported')

    for i in range(0, len(input_l)):

        kw = input_l[i][keyword_index]

        output = search_in_multi_list(input_l, kw, \
                keyword_type_str=_keyword_type_str, keyword_type_int=_keyword_type_int, \
                keyword_index=keyword_index, find_all=True)

        if (not output[0]):

            index_l.append(i)

        else:

            index_l.append(i)

            for i in range(1, len(output[1])):

                discard_l.append(output[1][i])

        discard_l = list(set(discard_l))

        for item in discard_l:

            if (item in index_l):

                try:

                    while (True):
                        index_l.pop(item)

                except IndexError:
                    pass

        index_l = list(set(index_l))

        output_l = []

        for index in index_l:
            item = input_l[index]
            output_l.append(item)

    # print(output_l)
    return output_l


def search_in_multi_list(l=[], keyword='', keyword_type_str=False,
        keyword_type_int=False, keyword_index=0, compare_value=False,
        value_index=1, value=-1, partial_match=False, find_all=False):

    """
    Supports auto detection of keyword type, so keyword_type_str or 
        keyword_type_int doesn't need to be specified

    * At this time only str and int data types are supported

    Also, supports advanced key:value search operations for str,
     very useful for example when parsing configurations etc. on Linux systems

    keyword =       Keyword to search for
    keyword_index = The index in multi list which will be used for the search

    value =         This compares values for matched up keyword
    value_index =   This is the index in multi list that will be considered

    """

    if (len(l) == 0):
        return l

    _keyword_type = None

    if (not (keyword_type_int or keyword_type_str)):

        data_type = l[0][keyword_index]

        if (type(data_type) == str):
            _keyword_type = str()
        elif (type(data_type) == int):
            _keyword_type = int()
        else:
            raise Exception('search_in_multi_list(): Unsupported data type detected')

    if (_keyword_type == int):

        if (find_all):

            index_l = []

            for i in range(0, len(l)):

                if (l[i][keyword_index] == keyword):
                    index_l.append(i)

            if (len(index_l) != 0):
                return (True, index_l)
            else:
                return (False, -1)

        else:

            for i in range(0, len(l)):

                if (l[i][keyword_index] == keyword):
                    return (True, [i])

            return (False, -1)

    else:

        if (compare_value):

            # This function supports key value pair comparison with partial match to remove duplicate entries

            if (partial_match):

                if (find_all):

                    index_l = []

                    for i in range(0, len(l)):
                        if (l[i][keyword_index].find(keyword) >= 0 and l[i][value_index] == value):
                            index_l.append(i)

                    if (len(index_l) != 0):
                        return (True, index_l)
                    else:
                        return (False, -1)

                else:

                    for i in range(0, len(l)):
                        if (l[i][keyword_index].find(keyword) >= 0 and l[i][value_index] == value):
                            return (True, [i])

                    return (False, -1)
            else:

                if (find_all):

                    index_l = []

                    for i in range(0, len(l)):
                        if (l[i][keyword_index] == keyword and l[i][value_index] == value):
                            index_l.append(i)

                    if (len(index_l) != 0):
                        return (True, index_l)
                    else:
                        return (False, -1)

                else:

                    for i in range(0, len(l)):
                        if (l[i][keyword_index] == keyword and l[i][value_index] == value):
                            return (True, [i])

                    return (False, -1)
        else:

            if (partial_match):

                if (find_all):

                    index_l = []

                    for i in range(0, len(l)):
                        if (l[i][keyword_index].find(keyword) >= 0):
                            index_l.append(i)

                    if (len(index_l) != 0):
                        return (True, index_l)
                    else:
                        return (False, -1)

                else:

                    for i in range(0, len(l)):
                        if (l[i][keyword_index].find(keyword) >= 0):
                            return (True, [i])

                    return (False, -1)
            else:

                if (find_all):

                    index_l = []

                    for i in range(0, len(l)):
                        if (l[i][keyword_index] == keyword):
                            index_l.append(i)

                    if (len(index_l) != 0):
                        return (True, index_l)
                    else:
                        return (False, -1)

                else:

                    for i in range(0, len(l)):
                        if (l[i][keyword_index] == keyword):
                            return (True, [i])

                    return (False, -1)


def main():

    try:
        parse_args()
    except KeyboardInterrupt:
        sys.exit(1)


if __name__ == '__main__':
    main()
