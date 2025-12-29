<?xml version="1.0" encoding="UTF-8" ?>
<xsl:stylesheet xmlns="event-logging:3" xmlns:stroom="stroom" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:map="http://www.w3.org/2005/xpath-functions/map" version="3.0">

  <!--
  Change Log:
  20251220:
  - Add support for all the 32 bit socketcall system calls
  20251219:
  - Add optional destination and source port numbers (dport and sport) to netfilter_pkt type records. Released to kernel 2025-12-17
  20250427:
  - Use map function rather and index lookup for Well Known NPE Linux user checks
  20250422:
  - Some systems generate two identical (so far seen) data/fanotify records, we need to cater for this 'bug'
  20250205:
  - Add support for additional uringop table entries
  20240922:
  - For chown, use emitUserId function for file ownership as it addresses User/Type
  - Decode the hex encoded device rule value for usbguard user_device events
  20240921:
  - Add internally defined _unknown_ user as a NPE user
  20231206:
  - Add support for syscall:close
  - As pretranslation filter no longer removes '-' from qnames, need to cater for certain hyphenated field names (prog-id, nl-mcgrp, old-level, new-level)
  - Uplift to schema 4.0.0
  - Implement EventSource/System/SecurityDomain (new from schema 4.0.0)
  
  20230903:
  - Add support to FANOTIFY reporting a'la
  type=PROCTITLE msg=audit(03/09/23 15:13:36.104:391) : proctitle=-bash 
  type=PATH msg=audit(03/09/23 15:13:36.104:391) : item=0 name=/tmp/ls inode=67150135 dev=fd:00 mode=file,755 ouid=burn ogid=burn rdev=00:00 obj=unconfined_u:object_r:user_tmp_t:s0 nametype=NORMAL cap_
  fp=none cap_fi=none cap_fe=0 cap_fver=0 cap_frootid=0 
  type=CWD msg=audit(03/09/23 15:13:36.104:391) : cwd=/home/burn 
  type=SYSCALL msg=audit(03/09/23 15:13:36.104:391) : arch=x86_64 syscall=execve success=no exit=EPERM(Operation not permitted) a0=0x563eb492de00 a1=0x563eb49456a0 a2=0x563eb492d850 a3=0x8 items=1 ppid
  =1792 pid=1823 auid=burn uid=burn gid=burn euid=burn suid=burn fsuid=burn egid=burn sgid=burn fsgid=burn tty=pts0 ses=1 comm=bash exe=/usr/bin/bash subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c
  0.c1023 key=cmds 
  type=FANOTIFY msg=audit(03/09/23 15:13:36.104:391) : resp=deny 
  
  20230630:
  TODO:
  Users of IPE require a way to identify when and why an operation fails,
  allowing them to both respond to violations of policy and be notified
  of potentially malicious actions on their systems with respect to IPE
  itself.
  
  This patch introduces 3 new audit events.
  
  AUDIT_IPE_ACCESS(1420) indicates the result of an IPE policy evaluation
  of a resource.
  AUDIT_IPE_CONFIG_CHANGE(1421) indicates the current active IPE policy
  has been changed to another loaded policy.
  AUDIT_IPE_POLICY_LOAD(1422) indicates a new IPE policy has been loaded
  into the kernel.
  
  This patch also adds support for success auditing, allowing users to
  identify why an allow decision was made for a resource. However, it is
  recommended to use this option with caution, as it is quite noisy.
  
  Here are some examples of the new audit record types:
  
  AUDIT_IPE_ACCESS(1420):
  
  audit: AUDIT1420 path="/root/vol/bin/hello" dev="sda"
  ino=3897 rule="op=EXECUTE boot_verified=TRUE action=ALLOW"
  
  audit: AUDIT1420 path="/mnt/ipe/bin/hello" dev="dm-0"
  ino=2 rule="DEFAULT action=DENY"
  
  audit: AUDIT1420 path="/tmp/tmpdp2h1lub/deny/bin/hello" dev="tmpfs"
  ino=131 rule="DEFAULT action=DENY"
  
  The above three records were generated when the active IPE policy only
  allows binaries from the initial booted drive(sda) to run. The three
  identical `hello` binary were placed at different locations, only the
  first hello from sda was allowed.
  
  Field path followed by the file's path name.
  
  Field dev followed by the device name as found in /dev where the file is
  from.
  Note that for device mappers it will use the name `dm-X` instead of
  the name in /dev/mapper.
  For a file in a temp file system, which is not from a device, it will use
  `tmpfs` for the field.
  The implementation of this part is following another existing use case
  LSM_AUDIT_DATA_INODE in security/lsm_audit.c
  
  Field ino followed by the file's inode number.
  
  Field rule followed by the IPE rule made the access decision. The whole
  rule must be audited because the decision is based on the combination of
  all property conditions in the rule.
  
  Along with the syscall audit event, user can know why a blocked
  happened. For example:
  
  audit: AUDIT1420 path="/mnt/ipe/bin/hello" dev="dm-0"
  ino=2 rule="DEFAULT action=DENY"
  audit[1956]: SYSCALL arch=c000003e syscall=59
  success=no exit=-13 a0=556790138df0 a1=556790135390 a2=5567901338b0
  a3=ab2a41a67f4f1f4e items=1 ppid=147 pid=1956 auid=4294967295 uid=0
  gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0
  ses=4294967295 comm="bash" exe="/usr/bin/bash" key=(null)
  
  The above two records showed bash used execve to run "hello" and got
  blocked by IPE. Note that the IPE records are always prior to a SYSCALL
  record.
  
  AUDIT_IPE_CONFIG_CHANGE(1421):
  
  audit: AUDIT1421
  old_active_pol_name="Allow_All" old_active_pol_version=0.0.0
  old_policy_digest=sha256:E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855
  new_active_pol_name="boot_verified" new_active_pol_version=0.0.0
  new_policy_digest=sha256:820EEA5B40CA42B51F68962354BA083122A20BB846F26765076DD8EED7B8F4DB
  auid=4294967295 ses=4294967295 lsm=ipe res=1
  
  The above record showed the current IPE active policy switch from
  `Allow_All` to `boot_verified` along with the version and the hash
  digest of the two policies. Note IPE can only have one policy active
  at a time, all access decision evaluation is based on the current active
  policy.
  The normal procedure to deploy a policy is loading the policy to deploy
  into the kernel first, then switch the active policy to it.
  
  AUDIT_IPE_POLICY_LOAD(1422):
  
  audit: AUDIT1422 policy_name="boot_verified" policy_version=0.0.0
  policy_digest=sha256:820EEA5B40CA42B51F68962354BA083122A20BB846F26765076DD8EED7B8F4DB
  auid=4294967295 ses=4294967295 lsm=ipe res=1
  
  The above record showed a new policy has been loaded into the kernel
  with the policy name, policy version and policy hash.
  
  
  20230614:
  - Cater for user_mac_status events - Trigger when a user space deamon effects an enforcing change
  - Cater for sauid uid values
  - Add avc content to processIncidentals
  20230601:
  - Cater for mac_ipc_event events
  - Cater for kernel events
  - Improve how Process/ProcessId is gained
  20230304:
  - Cater for multiple data/tty elements in a TTY capture event
  - Cater for multuple data//ses values in processIncidentals
  20230125:
  - Add support for the mmap2 system call (as a result of 32 bit architecture monitoring)
  - Add support for inotify_add_watch system call
  20230110:
  - Make adjtimex system calls updates or views depending if there is a time (AUDIT_TIME_INJOFFSET record) or time management change (AUDIT_TIME_ADJNTPVAL record)
  - In the case of time changes, add the time change concept as a third item type TypeId
  - Add reset and op to ProcessIncidentals
  - Add the errant unknown_1807_ for integrity_policy_rule
  - Ignore user_acct pam_tally2 events as other events cover account creation
  20221222:
  - When computing SourceEventid, incorrectly extracted millisecs. Fixed
  - Access* system calls are now modelled as a View (not update).
  - The mode attribute in a path element can have multiple strings before the mode (e.g file,suid,755) so we get the last value in a csv list. Fixed
  - Use correct system call argument for fchownat, fchmodat
  - Support user_tty messages
  20221221
  - Better model service_start/stop (have TypeId provide service name)
  - BPF calls are unsolicited and can be part of a syscall (if monitoring the bpf syscall), cater for this
  Note that BPF Unload program id is always zero (wef 20221221) based on the kernel code. Have requested a bug report be submitted,
  via the audit kernel mailing list.
  - We currently ignore single record BPF LOAD/UNLOAD events
  - Add exit value to processIncidentals
  - Improve openat|faccessat system call wrt flags location
  - Emit path incidentals for init_module
  - Emit path incidentals for various file releated activities
  - Emit dev in processIncidentals
  - Add syscall name in processIncidentals in case event is not a syscall
  - Support faccessat2, recvmsg, bpf, open_by_handle_at, tkill, tgkill and kill system calls
  20221220
  - Better model USER event (send message to auditd system)
  - Better model SECCOMP event (secure computing action)
  20221219
  - Add support for uringop calls
  - Re-work auditd configuration changes for general, feature and daemon config changes
  20220614
  - Add acct_lock to emit_IDAM
  20220126
  - Select the auid from the first matching subelement of all data/* elements
  - Be more specific when selecting the auid value from virt_control
  20211228
  - Added user_mac_config_change (user space daemon changes selinux config)
  20211222
  - Added resp_acct_lock (user account is locked)
  - Added resp_acct_lock_timed (user account is locked for a period of time)
  - Added resp_acct_unlock_timed (user account is unlocked after a period of time)
  - Added code to ignore user_acct/op/@i='start' messages
  20211221
  - Added modify-account for user_mgmt events
  20211117
  - Added support DAEMON_CONFIG - Triggered when a daemon configuration change is detected.
  - Added support for accessat and faccessat system calls
  20211114
  - Added support INTEGRITY_PCR - Triggered to record Platform Configuration Register (PCR) invalidation messages.
  20211107
  - Added comments to skipped events (justification)
  - Support EVENT_LISTENER (1335) records programs connecting/disconnecting to audit netlink multicast socket
  - Support SYSTEM_RUNLEVEL - Triggered when the system's run level is changed.
  - Support SYSTEM_SHUTDOWN - Triggered when the system is shut down.
  - Support DAEMON_ABORT - Triggered when a daemon is stopped due to an error.
  20211017 - Make a missing @host attribute which indicates a host can't resolve it's own hostname a Data element in Device rather than a warning to make stream maintenance easier
  - Add support for Selinux role_assign (TODO: complete all events)
  - Add support for Linux Integrity Subsystem (TODO: complete all events)
  - Add support for netfilter_cfg entries for Processors (clone syscall may have theses)
  - Treat unlock password as Account unlock
  - Support changed-password-aging, expired-password
  - Add support for fs_relabel
  - The ausearch bug resulting in events being split into two, is no longer a warning ... too many warnings makes for difficult stream maintenance
  - Evaludate integrity_data records within processIncidentals
  - Add support for mmap syscall
  20210918 - Conversion for V4 of schema where Location/TimeZone -> ../Data[@Name='TimeZone']
  20210915 - Add support for clone system call
  20210602 - Modifiy emitOutcome template to not record an outcome if the the activity succeded .. that is we assume success and only record failure.
  20210503 - Add support for openat2 systemcall
  20210101 - Add architecture value for syscalls
  20210101 - Add arch_prctl system call support
  20210101 - When generating the sub-action string check for multiple data//op elements - some firewall generated events provide mulitple data/netfilter_cfg (and hence data//op) subelements
  20210101 - Test for null Device/IPaddress
  20210101 - System/Environment element is mandatory
  20210101 - Need to strip prefix on transport protocols (ipv6-icmp becomes icmp) 
  20210101 - Some syscalls sttart with a netfilter_cfg element, cater for this
  20210101 - BPF events are explictily handled - previously there were just using their audit id of 1334
  20201229 - Note that cannonical timezones could have a preceeding 'posix/|right/|leaps/' string
  20201229 - Better support two path chown system calls
  20201229 - Note the node= can have a null value
  20201022 - Support stat system calls
  20201022 - Support FANOTIFY
  20201022 - Support type=USER
  20201022 - Support socketcall(connect)
  20201022 - Support netfilter_pkh systemcall
  20201022 - Better handle settimeofday events with only time_injoffset data tlements
  20200704 - Handle AUDIT_BPF == UNKNOWN_1334_ BPF Program Load/Unload actions
  20200608 - Better support seccomp and fix outcome bug where systemcall was not printed
  20200221 - Support Centos8 bug where AUDIT_TIME_ADJNTPVAL == UNKNOWN_1333_
  20200122 - Add support for USER_DEVICE records (e.g. from usbguard)
  20200108 - Ensure sockaddr/saddr values are saved when present in the Object
  20200107 - Add parsing for operation (register|replace) on NETFILTER_CFG parsing
  20200104 - More information in warning message when we get an unknwon event
  - Add support for sendto system call
  20191231 - Improve warning information when we get an unknown event
  - Add notes about CONTAINER_ID contid values (in template processIncidentals)
  20191212 - cater for sendmsg system calls
  20190818 - cater for time_adjntpval system calls
  -->

  <!-- Load the WellKnown Linux Users Index -->
  <xsl:variable name="evk" as="xs:string*">
    <xsl:for-each select="tokenize(stroom:dictionary('WellKnownLinuxNPEUsers'), '\n')[normalize-space()]">
      <xsl:if test="not(starts-with(normalize-space(.),'#'))">
        <xsl:value-of select="." />
      </xsl:if>
    </xsl:for-each>
  </xsl:variable>

  <!-- 20250427: Use map rather than index -->
  <xsl:variable name="wellKnownNPELinuxUsers" as="map(*)">
    <xsl:map>
      <xsl:for-each select="tokenize(stroom:dictionary('WellKnownLinuxNPEUsers'), '\n')[normalize-space()]">
        <xsl:if test="not(starts-with(normalize-space(.),'#'))">
          <xsl:map-entry key="lower-case(.)" />
        </xsl:if>
      </xsl:for-each>
    </xsl:map>
  </xsl:variable>

  <!-- Now match the inbound events -->
  <xsl:template match="log">
    <Events xsi:schemaLocation="event-logging:3 file://event-logging-v4.0.0.xsd" Version="4.0.0">
      <xsl:apply-templates />
    </Events>
  </xsl:template>

  <!-- Main record template -->
  <xsl:template match="event">
    <xsl:variable name="act" select="name(data/*[1])" />
    <xsl:variable name="terminal" select="data/*[name()=$act]/terminal/@i" />
    <xsl:choose>

      <!-- Skip Events Criteria -->

      <!-- 20211107: (for cron actions)
      user_end - Triggered when a user-space session is terminated.
      user_start - Triggered when a user-space session is started. 
      -->
      <xsl:when test="($act = 'user_end' or $act = 'user_start') and $terminal = 'cron'" />

      <!-- 20211107:
      crypto_failure_user - Triggered when a decrypt, encrypt, or randomize cryptographic operation fails. 
      crypto_ike_sa - Triggered when an Internet Key Exchange Security Association is established. 
      crypto_ipsec_sa - Triggered when an Internet Protocol Security Association is established. 
      crypto_key_user - Triggered to record the cryptographic key identifier used for cryptographic purposes. 
      crypto_login - Triggered when a cryptographic officer login attempt is detected. 
      crypto_logout - Triggered when a cryptographic officer logout attempt is detected. 
      crypto_param_change_user - Triggered when a change in a cryptographic parameter is detected. 
      crypto_replay_user - Triggered when a replay attack is detected. 
      crypto_session - Triggered to record parameters set during a TLS session establishment.
      crypto_test_user - Triggered to record cryptographic test results as required by the FIPS-139 standard.
      -->
      <xsl:when test="starts-with($act, 'crypto')" />

      <!-- 20211107: (Covered in other events)
      cred_acq - Triggered when a user acquires user-space credentials.
      cred_disp - Triggered when a user disposes of user-space credentials.
      cred_refr - Triggered when a user refreshes their user-space credentials.
      -->
      <xsl:when test="starts-with($act, 'cred_')" />

      <!-- 20211107: 
      login - Triggered to record relevant login information when a user log in to access the system. (Other events manage login)
      user_logout - Triggered when a user logs out. 
      user_auth - Triggered when a user-space user authentication attempt is detected. 
      
      -->
      <xsl:when test="starts-with($act, 'login')" />
      <xsl:when test="starts-with($act, 'user_logout')" />
      <xsl:when test="starts-with($act, 'user_auth')" />

      <!-- 20211107: -->
      <xsl:when test="starts-with($act, 'avc')" />

      <!-- 20211107:
      mac_config_change - Triggered when an SELinux Boolean value is changed.
      mac_policy_load - Triggered when a SELinux policy file is loaded.
      mac_status - Triggered when the SELinux mode (enforcing, permissive, off) is changed.
      user_labeled_export - Triggered when an object is exported with an SELinux label. 
      user_mac_policy_load - Triggered when a user-space daemon loads an SELinux policy. 
      user_mac_config_change - Triggered when an user-space daemon changed a SELinux Boolean value.
      user_role_change - Triggered when a user's SELinux role is changed.
      -->
      <xsl:when test="starts-with($act, 'mac_policy_load')" />
      <xsl:when test="starts-with($act, 'mac_status')" />
      <xsl:when test="starts-with($act, 'mac_config_change')" />
      <xsl:when test="starts-with($act, 'user_mac_policy_load')" />
      <xsl:when test="starts-with($act, 'user_labeled_export')" />
      <xsl:when test="starts-with($act, 'user_role_change')" />
      <xsl:when test="starts-with($act, 'user_mac_config_change')" />

      <!-- 20211107:
      user_avc - Triggered when a user-space AVC message is generated. 
      -->
      <xsl:when test="starts-with($act, 'user_avc')" />

      <!-- 20211107:
      mac_unlbl_allow - Triggered when unlabeled traffic is allowed when using the packet labeling capabilities of the kernel provided by NetLabel.
      mac_ublbl_stcadd - Triggered when a static label is added when using the packet labeling capabilities of the kernel provided by NetLabel.
      mac_unlbl_stcdel -Triggered when a static label is deleted when using the packet labeling capabilities of the kernel provided by NetLabel.
      mac_map_add - Triggered when a new Linux Security Module (LSM) domain mapping is added. LSM domain mapping is a part of the packet labeling capabilities of the kernel provided by NetLabel.
      mac_map_del - Triggered when an existing LSM domain mapping is added. LSM domain mapping is a part of the packet labeling capabilities of the kernel provided by NetLabel.
      -->
      <xsl:when test="starts-with($act, 'mac_unlbl_allow')" />
      <xsl:when test="starts-with($act, 'mac_unlbl_stcadd')" />
      <xsl:when test="starts-with($act, 'mac_unlbl_stcdel')" />
      <xsl:when test="starts-with($act, 'mac_map_add')" />
      <xsl:when test="starts-with($act, 'mac_map_del')" />

      <!-- Skip PAM: change authenticate tokens -->
      <xsl:when test="$act = 'user_chauthtok' and starts-with(.//op/@i, 'PAM')" />

      <!-- finit_module system call has no value, will need to rely on other events for useful information -->
      <xsl:when test="data/syscall/syscall/@i = 'finit_module'" />

      <!-- VIRT_MACHINE_ID reports the association of a security context with a guest -->
      <xsl:when test="starts-with($act, 'virt_machine_id')" />

      <!-- 20211107: ANOM_ audit types should be processed by an IDS
      anom_access_fs - Triggered when a file or a directory access ends abnormally. 
      anom_add_acct - Triggered when a user-space account addition ends abnormally. 
      anom_amtu_fail - Triggered when a failure of the Abstract Machine Test Utility (AMTU) is detected. 
      anom_crypto_fail - Triggered when a failure in the cryptographic system is detected. 
      anom_del_acct - Triggered when a user-space account deletion ends abnormally. 
      anom_exec - Triggered when an execution of a file ends abnormally. 
      anom_link - Triggered when suspicious use of file links is detected. 
      anom_login_acct - Triggered when an account login attempt ends abnormally. 
      anom_login_failures - Triggered when the limit of failed login attempts is reached. 
      anom_login_location - Triggered when a login attempt is made from a forbidden location. 
      anom_login_sessions - Triggered when a login attempt reaches the maximum amount of concurrent sessions. 
      anom_login_time - Triggered when a login attempt is made at a time when it is prevented by, for example, pam_time. 
      anom_max_dac - Triggered when the maximum amount of Discretionary Access Control (DAC) failures is reached. 
      anom_max_mac - Triggered when the maximum amount of Mandatory Access Control (MAC) failures is reached. 
      anom_mk_exec - Triggered when a file is made executable. 
      anom_mod_acct - Triggered when a user-space account modification ends abnormally. 
      anom_promiscuous - Triggered when a device enables or disables promiscuous mode. 
      anom_rbac_fail - Triggered when a Role-Based Access Control (RBAC) self-test failure is detected. 
      anom_rbac_integrity_fail - Triggered when a Role-Based Access Control (RBAC) file integrity test failure is detected. 
      anom_root_trans - Triggered when a user becomes root.
      
      -->
      <xsl:when test="starts-with($act, 'anom_')" />

      <!-- Skip operations: delete-shadow-group, add-shadow-group -->

      <!-- 20240510: No longer skip these -->

      <!--
      <xsl:when test="contains(data/grp_mgmt/op/@i,'-shadow-group')" />
      -->

      <!-- 20211107: And PAM:accounting or PAM:Authentication - we have other authentication events that cover these actions
      20211222: Ignore user_acct/op/@i='start' in addition to 'PAM:accounting'
      20230110: Also ignore user_acct/op/@i='pam_tally2'
      user_acct - Triggered when a user-space user authorization attempt is detected (op='PAM:accounting' or op='start')
      user_auth - Triggered when a user-space user authentication attempt is detected.
      20240508 - Allow user_acct/op/@i='PAM:accounting' as we gain client details
      -->
      <xsl:when test="matches(data/user_acct/op/@i,'start|pam_tally2')" />
      <xsl:when test="data/user_auth/op/@i = 'PAM:authentication'" />

      <!-- Don't record pam_tally2 resets -->
      <xsl:when test="data/user_mgmt/op/@i = 'pam_tally2' and data/user_mgmt/reset/@i = '0'" />

      <!-- 20221221: Don't record unsolicited BPF load or unload events as they have no value at the moment.
      Ensure we only target single record bpf events -->
      <xsl:when test="data/bpf and count(data/*)=1" />
      <xsl:otherwise>
        <Event>
          <xsl:element name="Meta">
            <xsl:copy-of select="stroom:source()" />
          </xsl:element>
          <xsl:variable name="_time">

            <!-- Cater for two timestamp formats as we gain events from
            aushape which uses ISO8601 - yyyy-MM-dd'T'HH:mm:ss.SSSZ
            ausearch which uses Linux - yyyy-MM-dd HH:mm:ss.SSS but fixed at UTC
            errant configured ausearch which uses MM/dd/yy HH:mm:ss.SSS fixed at UTC
            -->
            <xsl:choose>
              <xsl:when test="contains(@time, 'T')">
                <xsl:value-of select="stroom:format-date(replace(@time,'T',' '),'yyyy-MM-dd HH:mm:ss.SSSXXX')" />
              </xsl:when>
              <xsl:when test="matches(@time, '\d\d/\d\d/\d\d \d\d:\d\d:\d\d.\d\d\d')">
                <xsl:value-of select="stroom:format-date(@time, 'MM/dd/yy HH:mm:ss.SSS')" />
              </xsl:when>
              <xsl:otherwise>
                <xsl:value-of select="stroom:format-date(@time, 'yyyy-MM-dd HH:mm:ss.SSS')" />
              </xsl:otherwise>
            </xsl:choose>
          </xsl:variable>
          <xsl:call-template name="event_time">
            <xsl:with-param name="_time" select="$_time" />
          </xsl:call-template>
          <xsl:call-template name="event_source">
            <xsl:with-param name="_time" select="$_time" />
          </xsl:call-template>
          <xsl:call-template name="event_detail" />
          <Data Name="RawSource" Value="{concat(stroom:feed-name(), ':', stroom:source-id(), ':', stroom:part-no(), ':', stroom:record-no(), ':', stroom:line-from(), ':', stroom:col-from(), ':', stroom:line-to(), ':', stroom:col-to())}" />
        </Event>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <!-- Date time Group template -->
  <xsl:template name="event_time">
    <xsl:param name="_time" />
    <EventTime>
      <TimeCreated>
        <xsl:value-of select="$_time" />
      </TimeCreated>

      <!-- If we have been given a Canonical timezone name or a simple timezone value, then set this to the relative time -->
      <xsl:variable name="rtzone">
        <xsl:choose>
          <xsl:when test="stroom:meta('MyCanonicalTZ')">
            <xsl:value-of select="stroom:meta('MyCanonicalTZ')" />
          </xsl:when>
          <xsl:when test="stroom:meta('TZ')">
            <xsl:value-of select="stroom:meta('TZ')" />
          </xsl:when>
        </xsl:choose>
      </xsl:variable>
      <TimeSource>

        <!-- 
        Just in case we get an additional path item from the timezone calc by the agent we look for and remove the expected ones
        {posix|right|leaps/<iana timezone>
        -->
        <xsl:if test="string-length($rtzone) > 0">
          <Data Name="relativeTime" Value="{stroom:format-date(stroom:format-date($_time, 'yyyy-MM-dd''T''HH:mm:ss.SSSXXX'),'yyyy-MM-dd''T''HH:mm:ss.SSSXXX', 'Z','yyyy-MM-dd''T''HH:mm:ss.SSSXXX', replace($rtzone,'posix/|right/|leaps/',''))}" />
        </xsl:if>
        <Data Name="receiptTime" Value="{stroom:meta('ReceivedTime')}" />
      </TimeSource>
    </EventTime>
  </xsl:template>

  <!-- Event source -->
  <xsl:template name="event_source">
    <xsl:param name="_time" />
    <xsl:variable name="act" select="name(data/*[1])" />
    <xsl:variable name="_system" select="stroom:meta('System')" />
    <xsl:variable name="_env" select="stroom:meta('Environment')" />
    <xsl:variable name="_sdom" select="translate(stroom:meta('MySecurityDomain'), '&quot;', '')" />
    <xsl:variable name="_auid">

      <!-- Normally the auditing user id only appears once in an event. Cater for known cases when this is not the case -->
      <xsl:choose>
        <xsl:when test="./data/mac_config_change/auid">
          <xsl:value-of select="./data/mac_config_change/auid/@i" />
        </xsl:when>
        <xsl:when test="./data/integrity_data/auid">
          <xsl:value-of select="./data/integrity_data/auid/@i" />
        </xsl:when>
        <xsl:when test="./data/integrity_pcr/auid">
          <xsl:value-of select="./data/integrity_pcr/auid/@i" />
        </xsl:when>
        <xsl:when test="./data/virt_control/auid/@i">

          <!-- 20220126 -->
          <xsl:value-of select="./data/virt_control/auid/@i" />
        </xsl:when>

        <!-- 20220126 - Select the auid from the first matching subelement -->
        <xsl:when test="./data//auid/@i">
          <xsl:value-of select="./data/*[position()=1]/auid/@i" />
        </xsl:when>
        <xsl:when test="./data/user_login/id/@i">
          <xsl:value-of select="./data/user_login/id/@i" />
        </xsl:when>
        <xsl:when test="./data/user_start/acct/@i">
          <xsl:value-of select="./data/user_start/acct/@i" />
        </xsl:when>
      </xsl:choose>
    </xsl:variable>

    <!-- Note that some events, have two hostnames as per
    type=VIRT_CONTROL msg=audit(2017-09-15 11:26:07.703:16414) : pid=2762 uid=root auid=unset ses=unset subj=system_u:system_r:container_runtime_t:s0 msg='op=start vm-pid=? user=origin auid=unknown(1002) reason=api exe=? hostname=? vm=? exe=/usr/bin/dockerd-current hostname=? addr=? terminal=? res=success' 
    As both aushape and the preTranslation transformation reverses the order of key value pairs, the hostname we are after for clientH (ie the last one above) becomes the first one.
    The following will gain the host name whether we have one or more hostname key value pairs
    -->
    <xsl:variable name="_clientH" select="./data//hostname[1]/@i" />
    <xsl:variable name="_clientI" select="./data//addr/@i" />

    <!-- 20240510: Improve the collection of uid value
    <xsl:variable name="_uid" select="data/syscall/uid[1]/@i|data/user_end/uid/@i" />
    -->
    <xsl:variable name="_uid">
      <xsl:choose>
        <xsl:when test="./data//uid/@i">
          <xsl:value-of select="./data/*[position()=1]/uid/@i" />
        </xsl:when>
      </xsl:choose>
    </xsl:variable>
    <xsl:variable name="_myhost" select="translate(stroom:meta('MyHost'),'&quot;', '')" />
    <xsl:variable name="_myip" select="translate(stroom:meta('MyIPaddress'),'&quot;', '')" />
    <xsl:variable name="_mymeta" select="translate(stroom:meta('MyMeta'),'&quot;', '')" />
    <xsl:variable name="_myns" select="translate(stroom:meta('MyNameServer'),'&quot;', '')" />
    <xsl:variable name="_deviceHostName">

      <!-- For the device host name we choose, in order, contents of
      - MyHost header variable in post
      - FQDN portion of MyMeta header variable in post
      - @host attribute on the event element providing it's not null
      - the 'RemoteHost' attribute that Stroom's proxy evaluated
      -->
      <xsl:choose>
        <xsl:when test="string-length($_myhost) > 0 and contains($_myhost, ' ')">
          <xsl:value-of select="substring-before($_myhost, ' ')" />
        </xsl:when>
        <xsl:when test="string-length($_myhost) > 0">
          <xsl:value-of select="$_myhost" />
        </xsl:when>
        <xsl:when test="string-length($_mymeta) > 0">
          <xsl:value-of select="substring-before(substring-after($_mymeta,'FQDN:'),'\')" />
        </xsl:when>
        <xsl:when test="@host and string-length(@host) > 0">
          <xsl:value-of select="@host" />
        </xsl:when>
        <xsl:otherwise>
          <xsl:value-of select="stroom:meta('RemoteHost')" />
        </xsl:otherwise>
      </xsl:choose>
    </xsl:variable>

    <!-- If we have a @host and it's empty then complain as the source host cannot resolve itself! This means a bad agent. -->

    <!-- DEPRICATED: 20211017; We now record this fact in the EventSource/Device element, as the warnings make for difficult stream maintenance -->

    <!--
    <xsl:if test="@host and string-length(@host) = 0">
    <xsl:value-of select="stroom:log('WARN', concat('Stream Id: ', stroom:stream-id(), ' has a null node= value. T/E:', @time, '/', @serial, ' MyIPaddress:', $_myip, ' MyNameServer:', $_myns, ' RemoteHost:', stroom:meta('RemoteHost')))" />
    </xsl:if>
    -->

    <!-- -->
    <xsl:variable name="_deviceIP">

      <!-- For the device ip address we choose, in order, contents of
      - MyHost header variable in post
      - ipaddress portion of MyMeta header variable in post
      - the 'RemoteAddress' attribute that Stroom's proxy evaluated
      -->
      <xsl:choose>
        <xsl:when test="string-length($_myip) > 0 and contains($_myip, ' ')">
          <xsl:value-of select="substring-before($_myip, ' ')" />
        </xsl:when>
        <xsl:when test="string-length($_myip) > 0 and contains($_myip, '%')">
          <xsl:value-of select="substring-before($_myip, '%')" />
        </xsl:when>
        <xsl:when test="string-length($_myip) > 0">
          <xsl:value-of select="$_myip" />
        </xsl:when>
        <xsl:when test="string-length($_mymeta) > 0">
          <xsl:value-of select="substring-before(substring-after($_mymeta,'ipaddress:'),'\')" />
        </xsl:when>
        <xsl:otherwise>
          <xsl:value-of select="stroom:meta('RemoteAddress')" />
        </xsl:otherwise>
      </xsl:choose>
    </xsl:variable>

    <!-- Now fill in the EventSource element -->
    <EventSource>
      <System>
        <Name>
          <xsl:choose>
            <xsl:when test="string-length($_system) > 0">
              <xsl:value-of select="$_system" />
            </xsl:when>
            <xsl:otherwise>
              <xsl:value-of select="substring-before(stroom:feed-name(), '-EVENTS')" />
            </xsl:otherwise>
          </xsl:choose>
        </Name>

        <!-- Environment is mandatory 20210101 -->
        <Environment>
          <xsl:choose>
            <xsl:when test="string-length($_env) > 0">
              <xsl:value-of select="$_env" />
            </xsl:when>
            <xsl:otherwise>Production</xsl:otherwise>
          </xsl:choose>
        </Environment>

        <!-- 20231206: SecurityDomain is available for schema 4.0.0 and above -->
        <xsl:if test="string-length($_sdom) > 0">
          <SecurityDomain>
            <xsl:value-of select="$_sdom" />
          </SecurityDomain>
        </xsl:if>
        <xsl:if test="stroom:meta('Version')">
          <Version>
            <xsl:value-of select="stroom:meta('Version')" />
          </Version>
        </xsl:if>
      </System>
      <Generator>Linux Auditd/Aushape/Ausearch</Generator>
      <Device>
        <HostName>
          <xsl:value-of select="$_deviceHostName" />
        </HostName>

        <!-- Test for contents 20210101 -->
        <xsl:if test="string-length($_deviceIP)">
          <IPAddress>
            <xsl:value-of select="$_deviceIP" />
          </IPAddress>
        </xsl:if>

        <!-- 20210918 Conversion for V4 of schema where
        Location/TimeZone -> ../Data[@Name='TimeZone']
        -->
        <xsl:if test="stroom:meta('MyCanonicalTZ')">
          <Location>
            <TimeZoneName>
              <xsl:value-of select="replace(stroom:meta('MyCanonicalTZ'),'posix/|right/|leaps/','') " />
            </TimeZoneName>
          </Location>
        </xsl:if>
        <xsl:if test="stroom:meta('MyTZ')">
          <Data Name="TimeZone" Value="{stroom:meta('MyTZ')}" />
        </xsl:if>
        <xsl:if test="string-length($_myns) > 0">
          <Data Name="NameServer" Value="{$_myns}" />
        </xsl:if>

        <!-- 20211017: Record missing @host details here -->
        <xsl:if test="@host and string-length(@host) = 0">
          <Data Name="MissingNode" Value="{concat('Stream Id: ', stroom:stream-id(), ' has a null node= value ',' T/E:', @time, '/', @serial, ' MyIPaddress:', $_myip, ' NameServer:', $_myns, ' RemoteHost:', stroom:meta('RemoteHost'))}" />
        </xsl:if>
      </Device>
      <xsl:if test="($_clientH != '' and not(contains($_clientH, '?'))) or ($_clientI != '' and not(contains($_clientI, '?')))">
        <Client>
          <xsl:choose>
            <xsl:when test="contains($_clientH, 'localhost')">
              <HostName>
                <xsl:value-of select="$_deviceHostName" />
              </HostName>
            </xsl:when>
            <xsl:when test="$_clientH != '' and not(contains($_clientH,'?')) ">
              <HostName>
                <xsl:value-of select="$_clientH" />
              </HostName>
            </xsl:when>
          </xsl:choose>
          <xsl:choose>
            <xsl:when test="$_clientI eq ''" />
            <xsl:when test="contains($_clientI, '%')">
              <IPAddress>
                <xsl:value-of select="substring-after($_clientI, '%')" />
              </IPAddress>
            </xsl:when>
            <xsl:when test=" not(contains($_clientI,'?')) and $_clientI ne '127.0.0.1' and $_clientI ne 'UNKNOWN'">
              <IPAddress>
                <xsl:value-of select="$_clientI" />
              </IPAddress>
            </xsl:when>
          </xsl:choose>
        </Client>
      </xsl:if>

      <!-- User details -->
      <xsl:if test="string-length($_auid) > 0">
        <User>
          <xsl:call-template name="emitUserId">
            <xsl:with-param name="_u" select="$_auid" />
          </xsl:call-template>
        </User>
      </xsl:if>
      <xsl:if test="$_auid != $_uid and not(starts-with($act, 'user_') or $act = 'user_chauthok')">
        <RunAs>
          <xsl:call-template name="emitUserId">
            <xsl:with-param name="_u" select="$_uid" />
          </xsl:call-template>
        </RunAs>
      </xsl:if>
      <Data Name="FeedName">
        <xsl:attribute name="Value">
          <xsl:value-of select="stroom:feed-name()" />
        </xsl:attribute>
      </Data>

      <!-- Recreate the original source event id which is of the form <secs>.<msecs>:<serial> -->
      <Data Name="SourceEventid">
        <xsl:attribute name="Value">
          <xsl:variable name="ms" select="xs:string((xs:dateTime($_time) - xs:dateTime('1970-01-01T00:00:00.000Z')) div xs:dayTimeDuration('PT0.001S'))" as="xs:string" />
          <xsl:variable name="msl" select="string-length($ms)" as="xs:decimal" />

          <!-- 20221222: Fix bug to get correct millisec -->
          <xsl:value-of select="concat(substring($ms, 1, $msl - 3), '.', substring($ms, $msl - 2, 3),':', @serial)" />
        </xsl:attribute>
      </Data>
    </EventSource>
  </xsl:template>

  <!-- Event detail -->
  <xsl:template name="event_detail">

    <!-- Get the first child element of the event's main data element - this is the Auditd 'type' for the event
    If the name is selinux_err, then skip to the second element as this event is a selinux_error about the next element
    If the name is time_adjntpval, then skip to the second element as this events is a time adjustment system call (20190818)
    If the name is netfilter_cfg and we have a syscall, then use the syscall sub-element (20210101)
    audit_bpf is now bpf (20210101)
    If the name is integrity_data and we have a syscall, then use the syscall sub-element (20211017)
    This is because we don't want 'integrity_data' to be the subject of the audit event, it should only be an informed piece of information.
    Add the errant unknown_1807_ for integrity_policy_rule (20230110)
    -->
    <xsl:variable name="act">
      <xsl:choose>
        <xsl:when test="name(data/*[1]) = 'selinux_err'">
          <xsl:value-of select="name(data/*[2])" />
        </xsl:when>
        <xsl:when test="name(data/*[1]) = 'time_adjntpval' or name(data/*[1]) = 'unknown_1333_' or name(data/*[1]) = 'time_injoffset'">
          <xsl:value-of select="name(data/syscall)" />
        </xsl:when>
        <xsl:when test="name(data/*[1]) = 'unknown_1334_'">bpf</xsl:when>
        <xsl:when test="name(data/*[1]) = 'unknown_1335_'">event_listener</xsl:when>
        <xsl:when test="name(data/*[1]) = 'unknown_1138_'">software_update</xsl:when>
        <xsl:when test="name(data/*[1]) = 'unknown_1807_'">integrity_policy_rule</xsl:when>
        <xsl:when test="name(data/*[1]) = 'netfilter_cfg' and data/syscall">
          <xsl:value-of select="name(data/syscall)" />
        </xsl:when>
        <xsl:when test="name(data/*[1]) = 'integrity_data' and data/syscall">
          <xsl:value-of select="name(data/syscall)" />
        </xsl:when>

        <!-- 20221221: If an unsolicted BPF event is associated with a syscall, the syscall wins -->
        <xsl:when test="name(data/*[1]) = 'bpf' and data/syscall">
          <xsl:value-of select="name(data/syscall)" />
        </xsl:when>
        <xsl:otherwise>
          <xsl:value-of select="name(data/*[1])" />
        </xsl:otherwise>
      </xsl:choose>
    </xsl:variable>
    <xsl:variable name="subact">

      <!-- Certain actions have sub actions -->
      <xsl:choose>

        <!-- Support uringop - 20221219 -->
        <xsl:when test="$act='uringop'">

          <!-- Note the uring_op can be a number or text depending on ausearch version -->
          <xsl:variable name="uringop_map" select="
            map { 
            '0' : 'nop','1' : 'readv','2' : 'writev','3' : 'fsync','4' : 'read_fixed','5' : 'write_fixed','6' : 'poll_add','7' : 'poll_remove','8' : 'sync_file_range','9' : 'sendmsg',
            '10' : 'recvmsg','11' : 'timeout','12' : 'timeout_remove','13' : 'accept','14' : 'async_cancel','15' : 'link_timeout','16' : 'connect','17' : 'fallocate','18' : 'openat',
            '19' : 'close','20' : 'files_update','21' : 'statx','22' : 'read','23' : 'write','24' : 'fadvise','25' : 'madvise','26' : 'send','27' : 'recv','28' : 'openat2','29' : 'epoll_ctl',
            '30' : 'splice','31' : 'provide_bufers','32' : 'remove_bufers','33' : 'tee','34' : 'shutdown','35' : 'renameat','36' : 'unlinkat', '37' :  'mkdirat', '38' :  'symlinkat',
            '39' :  'linkat', '40' :  'msg_ring', '41' :  'fsetxattr', '42' :  'setxattr', '43' :  'fgetxattr', '44' :  'getxattr', '46' :  'uring_cmd', '48' : 'sendmsg_zc', 
            '50' :  'waitid', '51' :  'futex_wait', '52' :  'futex_wake', '53' :  'futex_waitv', '54' :  'fixed_fd_install', '55' :  'ftruncate', '56' :  'bind', '57' :  'listen'

            }">      
          </xsl:variable>
          <xsl:choose>
            <xsl:when test="string(number(data/uringop/uring_op/@i))!= 'NaN'">
              <xsl:value-of select="concat(data/syscall/syscall/@i, ':', $uringop_map(data/uringop/uring_op/@i))" />
            </xsl:when>
            <xsl:otherwise>
              <xsl:value-of select="concat(data/syscall/syscall/@i, ':', data/uringop/uring_op/@i)" />
            </xsl:otherwise>
          </xsl:choose>
        </xsl:when>
        <xsl:when test="$act='syscall'">
          <xsl:value-of select="data/syscall/syscall/@i" />
        </xsl:when>

        <!-- 20240511: For grp_mgmt and grp_chauthtok events the op is the complete message from the shadow-utils utility (groupmod, etc) as per
        -n
        grp_mgmt changing /etc/group; group <group_name>/<gid>, new name: <name>
        grp_mgmt changing /etc/gshadow; group <group_name>, new name: <name>
        grp_mgmt changing /etc/passwd; group <group_name>/<gid, new name: <name>
        -p
        grp_mgmtchanging /etc/group; group <group_name>/<gid>, new password
        -g
        grp_mgmt changing /etc/group; group <group_name>/<gid>, new gid: <gid>
        grp_mgmt changing /etc/passwd; group <group_name>/<gid, new gud: <gid>
        
        So if changing, then set subact to be the string 'changing <file>'
        -->
        <xsl:when test="matches($act,'grp_mgmt|grp_chauthtok') and starts-with(data//op/@i, 'changing /')">
          <xsl:value-of select="substring-before(data//op/@i, ';')" />
        </xsl:when>

        <!-- When generating the sub-action string check for multiple data//op elements - some firewall generated events provide mulitple data/netfilter_cfg (and hence data//op) subelements 20210101 -->
        <xsl:when test="count(data//op) = 1">
          <xsl:value-of select="replace(data//op/@i,'&quot;', '')" />
        </xsl:when>
        <xsl:when test="data/virt_resource/reason">
          <xsl:value-of select="data/virt_resource/reason/@i" />
        </xsl:when>
        <xsl:when test="$act='seccomp'">
          <xsl:value-of select="data/seccomp/syscall/@i" />
        </xsl:when>
        <xsl:when test="data/fanotify and data/syscall">

          <!-- 20250422: Can have multiple data/fanotify records -->
          <xsl:value-of select="concat(data/syscall/syscall/@i, ':', distinct-values(data/fanotify/resp/@i))" />
        </xsl:when>
        <xsl:when test="$act='software_update'">
          <xsl:value-of select="data//sw_type/@i" />
        </xsl:when>

        <!-- 20221220: User message -->
        <xsl:when test="$act='user'">send_message_to_auditd_system</xsl:when>

        <!-- 20221221: Service Start/Stop to provide service name -->
        <xsl:when test="$act='service_start' or $act='service_stop'">
          <xsl:value-of select="data/service_start/unit/@i|data/service_stop/unit/@i" />
        </xsl:when>

        <!-- 20230601: When we get a kernel type message, it indicates the kernel audit has just initialised -->
        <xsl:when test="$act='kernel'">auditd_initialisation</xsl:when>
      </xsl:choose>
    </xsl:variable>
    <EventDetail>
      <TypeId>
        <xsl:choose>
          <xsl:when test="$act = $subact">
            <xsl:value-of select="concat($act, ':')" />
          </xsl:when>
          <xsl:when test="$act = ''">UnknownAction</xsl:when>
          <xsl:otherwise>
            <xsl:value-of select="concat($act, ':', $subact)" />
          </xsl:otherwise>
        </xsl:choose>

        <!-- 20230110: In the case of time changes, add the time change concept as a third item type TypeId -->
        <xsl:choose>
          <xsl:when test="data/time_adjntpval|data/unknown_1333_">
            <xsl:value-of select="':time_adjntpval'" />
          </xsl:when>
          <xsl:when test="data/time_injoffset">
            <xsl:value-of select="':time_injoffset'" />
          </xsl:when>
        </xsl:choose>
      </TypeId>

      <!-- Switch on the action -->
      <xsl:choose>

        <!-- An alert/error from aushape -->
        <xsl:when test="string-length($act) = 0">
          <Alert>
            <Type>Error</Type>
            <Description>
              <xsl:value-of select="@error" />
            </Description>
          </Alert>
        </xsl:when>

        <!-- User_Device -->
        <xsl:when test="($act='user_device')">
          <xsl:call-template name="emitUserDevice">
            <xsl:with-param name="op" select="$subact" />
          </xsl:call-template>
        </xsl:when>

        <!-- Umask -->
        <xsl:when test="($act='syscall' and $subact='umask')">
          <xsl:call-template name="emitUmask" />
        </xsl:when>

        <!-- Execve - process execution -->
        <xsl:when test="($act='syscall' and $subact='execve') or ($act='user_cmd') or ($act = 'anom_abend')  or ($act = 'execve') or ($act = 'seccomp') or ($act = 'user') or ($act = 'uringop')">
          <xsl:call-template name="processEvent">
            <xsl:with-param name="processAction" select="'Execute'" />
            <xsl:with-param name="processType" select="'OS'" />
          </xsl:call-template>
        </xsl:when>

        <!-- Process tracing -->
        <xsl:when test="($act='syscall' and $subact='ptrace')">
          <xsl:call-template name="processEvent">
            <xsl:with-param name="processAction" select="'Execute'" />
            <xsl:with-param name="processType" select="'OS'" />
          </xsl:call-template>
        </xsl:when>

        <!-- 20221221: Kill processes -->
        <xsl:when test="($act='syscall' and matches($subact, 'kill'))">
          <xsl:call-template name="processEvent">
            <xsl:with-param name="processAction" select="'Terminate'" />
            <xsl:with-param name="processType" select="'OS'" />
          </xsl:call-template>
        </xsl:when>

        <!-- 20221222 - User_TTY -->
        <xsl:when test="$act = 'user_tty'">
          <xsl:call-template name="processEvent">
            <xsl:with-param name="processAction" select="'Execute'" />
            <xsl:with-param name="processType" select="'OS'" />
          </xsl:call-template>
        </xsl:when>

        <!-- user/group management -->

        <!-- 20220614: Add acct_lock -->
        <xsl:when test="data/user_mgmt|data/del_user|data/del_group|data/grp_mgmt|data/add_user|data/add_group|data/chgrp_id|data/acct_unlock|data/resp_acct_unlock_timed|data/resp_acct_lock|data/acct_lock">
          <xsl:call-template name="emitIDAM">
            <xsl:with-param name="act" select="$act" />
            <xsl:with-param name="subact" select="$subact" />
          </xsl:call-template>
        </xsl:when>

        <!-- 20211017: Selinux -->
        <xsl:when test="data/role_assign">
          <xsl:call-template name="emitSelinuxRoles" />
        </xsl:when>

        <!-- 20230614: user_mac_status -->
        <xsl:when test="data/user_mac_status">
          <xsl:call-template name="emitSelinuxUpdate" />
        </xsl:when>

        <!-- 20211017: Linux Integrity Subsystem -->

        <!-- Sometimes we will get a INTEGRITY_DATA event all by itself. We cater for that here. -->
        <xsl:when test="matches($act, 'integrity_policy_rule|integrity_data')">
          <xsl:call-template name="emitIMA">
            <xsl:with-param name="act" select="$act" />
            <xsl:with-param name="subact" select="$subact" />
          </xsl:call-template>
        </xsl:when>

        <!-- 20211114 Deal with IMA ReadWrite Violation -->
        <xsl:when test="$act='integrity_pcr' and $subact='invalid_pcr'">
          <xsl:call-template name="emitIntegrityPcr" />
        </xsl:when>

        <!-- Authentication -->
        <xsl:when test="data/user_end|data/user_start|data/user_login|data/user_acct|data/user_err">
          <xsl:call-template name="emitAuthenticate" />
        </xsl:when>
        <xsl:when test="data/user_chauthtok and not(starts-with($subact, 'PAM'))">
          <xsl:call-template name="emitAuthenticate" />
        </xsl:when>

        <!-- chown|chgrp -->
        <xsl:when test="$act='syscall' and (contains($subact,'chown') or contains($subact, 'chgrp'))">
          <xsl:call-template name="emitChown" />
        </xsl:when>

        <!-- chmod -->
        <xsl:when test="$act='syscall' and contains($subact,'chmod')">
          <xsl:call-template name="emitChmod" />
        </xsl:when>

        <!-- chdir -->
        <xsl:when test="$act='syscall' and contains($subact,'chdir')">
          <xsl:call-template name="emitChdir" />
        </xsl:when>

        <!-- rmdir|unlink -->
        <xsl:when test="$act='syscall' and matches($subact,'rmdir|unlink')">
          <xsl:call-template name="emitDelete" />
        </xsl:when>

        <!-- setuid|setresuid|setgid|setresgid -->
        <xsl:when test="$act='syscall' and matches($subact,'setuid|setresuid|setgid|setresgid')">
          <xsl:call-template name="emitSetuid" />
        </xsl:when>

        <!-- mkdir -->
        <xsl:when test="$act='syscall' and matches($subact,'mkdir|mknod')">
          <xsl:call-template name="emitMkdir" />
        </xsl:when>

        <!-- readlink -->
        <xsl:when test="$act = 'syscall' and $subact = 'readlink'">
          <xsl:call-template name="emitOpen" />
        </xsl:when>

        <!-- swapon -->
        <xsl:when test="$act = 'syscall' and matches($subact, 'swapon')">
          <xsl:call-template name="emitOpen" />
        </xsl:when>

        <!-- linkat|symlink -->
        <xsl:when test="$act='syscall' and matches($subact,'^link|linkat|symlink|symlinkat')">
          <xsl:call-template name="emitLink" />
        </xsl:when>

        <!-- *setxattr -->
        <xsl:when test="$act='syscall' and matches($subact,'setxattr|removexattr|listxattr|getxattr')">
          <xsl:call-template name="emitSetxattr" />
        </xsl:when>

        <!-- open -->

        <!-- 20221221: Add faccessat2 -->
        <xsl:when test="$act='syscall' and matches($subact,'^open|^access|accessat$|accessat2$')">
          <xsl:call-template name="emitOpen" />
        </xsl:when>

        <!-- time -->

        <!-- 20230110: Make time or time management changes an update, otherwise make it a view -->
        <xsl:when test="$act='syscall' and contains($subact,'time')">
          <xsl:choose>
            <xsl:when test="data/time_adjntpval|data/time_injoffset|data/unknown_1333_">
              <xsl:call-template name="emitConfigChange">
                <xsl:with-param name="_change" select="'Time'" />
              </xsl:call-template>
            </xsl:when>
            <xsl:otherwise>
              <View>
                <Configuration>
                  <Type>Time</Type>
                </Configuration>
                <xsl:call-template name="emitOutcome" />
                <xsl:call-template name="processIncidentals" />
              </View>
            </xsl:otherwise>
          </xsl:choose>
        </xsl:when>

        <!-- TTY recording -->
        <xsl:when test="$act='tty'">
          <xsl:call-template name="emitTTY" />
        </xsl:when>

        <!-- hostname -->
        <xsl:when test="$act='syscall' and contains($subact,'hostname')">
          <xsl:call-template name="emitConfigChange">
            <xsl:with-param name="_change" select="'HostName'" />
          </xsl:call-template>
        </xsl:when>

        <!-- usys_config -->
        <xsl:when test="$act = 'usys_config'">
          <xsl:call-template name="emitConfigChange">
            <xsl:with-param name="_change" select="data/usys_config/op/@i" />
          </xsl:call-template>
        </xsl:when>

        <!-- fs_relabel -->
        <xsl:when test="$act = 'fs_relabel'">
          <xsl:call-template name="emitConfigChange">
            <xsl:with-param name="_change" select="data/fs_relabel/op/@i" />
          </xsl:call-template>
        </xsl:when>

        <!-- 20211107:
        system_runlevel - Triggered when the system's run level is changed.
        -->
        <xsl:when test="$act='system_runlevel'">
          <xsl:call-template name="emitConfigChange">
            <xsl:with-param name="_change" select="'SystemRunLevel'" />
          </xsl:call-template>
        </xsl:when>

        <!-- create -->
        <xsl:when test="$act='syscall' and (contains($subact,'creat') or contains($subact, 'truncate'))">
          <xsl:call-template name="emitCreate" />
        </xsl:when>

        <!-- rename -->
        <xsl:when test="$act='syscall' and matches($subact,'rename')">
          <xsl:call-template name="emitMove" />
        </xsl:when>

        <!-- Mount/unmount -->
        <xsl:when test="$act='syscall' and contains($subact, 'mount')">
          <xsl:call-template name="processEvent">
            <xsl:with-param name="processAction" select="'Execute'" />
            <xsl:with-param name="processType" select="'OS'" />
          </xsl:call-template>
        </xsl:when>

        <!-- Connect/Accept/Bind Get|Set Sockopt -->

        <!-- 20221221: Add recvmsg -->
        <xsl:when test="$act='syscall' and (starts-with($subact, 'accept') or $subact='connect' or $subact = 'bind' or $subact = 'sendto' or $subact = 'sendmsg' or $subact = 'recvmsg' or ends-with($subact,'etsockopt') or starts-with($subact, 'socketcall'))">
          <xsl:call-template name="emitExternalConnection">
            <xsl:with-param name="_sact" select="$subact" />
          </xsl:call-template>
        </xsl:when>

        <!-- sockaddr -->
        <xsl:when test="$act = 'sockaddr'">
          <xsl:call-template name="emitExternalConnection">
            <xsl:with-param name="_sact" select="$act" />
          </xsl:call-template>
        </xsl:when>

        <!-- netfilter_cfg -->
        <xsl:when test="$act = 'netfilter_cfg'">
          <xsl:call-template name="emitNetFilterCfg" />
        </xsl:when>

        <!-- netfilter_pkt -->
        <xsl:when test="$act = 'netfilter_pkt'">
          <xsl:call-template name="emitNetFilterPkt" />
        </xsl:when>

        <!-- 20211107 - Audit Netlink connection alert -->
        <xsl:when test="$act = 'event_listener'">
          <xsl:call-template name="emitAlert">
            <xsl:with-param name="_sact" select="$act" />
          </xsl:call-template>
        </xsl:when>

        <!-- 20230601: mac_ipsec_events XFRM IPSec management -->
        <xsl:when test="$act = 'mac_ipsec_event'">
          <xsl:call-template name="emitXFRM">
            <xsl:with-param name="_sact" select="$subact" />
          </xsl:call-template>
        </xsl:when>

        <!-- Audit daemon config changes -->

        <!-- 20221219 - Redo configuration changes -->
        <xsl:when test="data/config_change">
          <xsl:call-template name="auditConfigChange_config" />
        </xsl:when>
        <xsl:when test="data/feature_change">
          <xsl:call-template name="auditConfigChange_feature" />
        </xsl:when>
        <xsl:when test="data/daemon_config">
          <xsl:call-template name="auditConfigChange_daemon" />
        </xsl:when>

        <!-- Audit daemon service -->

        <!-- 20230601: Add kernel test -->
        <xsl:when test="$act='daemon_start' or $act='service_start' or $act = 'system_boot' or $act = 'kernel'">
          <xsl:call-template name="processEvent">
            <xsl:with-param name="processAction" select="'Startup'" />
            <xsl:with-param name="processType" select="'Service'" />
          </xsl:call-template>
        </xsl:when>

        <!-- 20211107:
        -->
        <xsl:when test="$act='daemon_end' or $act='service_stop' or $act='system_shutdown' or $act='daemon_abort'">
          <xsl:call-template name="processEvent">
            <xsl:with-param name="processAction" select="'Shutdown'" />
            <xsl:with-param name="processType" select="'Service'" />
          </xsl:call-template>
        </xsl:when>

        <!-- Modules -->
        <xsl:when test="$act='syscall' and $subact='delete_module'">
          <xsl:call-template name="emitDeleteModule" />
        </xsl:when>
        <xsl:when test="$act='syscall' and $subact='init_module'">
          <xsl:call-template name="emitCreateModule" />
        </xsl:when>

        <!-- Virtualisation -->
        <xsl:when test="$act='virt_resource'">
          <xsl:call-template name="emitVirtualResource" />
        </xsl:when>
        <xsl:when test="$act='virt_control'">
          <xsl:call-template name="emitVirtualControl" />
        </xsl:when>

        <!-- Acct system call -->
        <xsl:when test="$act = 'syscall' and $subact = 'acct'">
          <xsl:call-template name="emitAcct" />
        </xsl:when>

        <!-- arch_prctl system call (20210101) -->
        <xsl:when test="$act = 'syscall' and $subact = 'arch_prctl'">
          <xsl:call-template name="emitArchThreadState" />
        </xsl:when>

        <!-- Container operation -->
        <xsl:when test="$act = 'container_op'">
          <xsl:call-template name="emitContainerOp" />
        </xsl:when>

        <!-- Namespace system calls -->
        <xsl:when test="$act = 'syscall' and matches($subact, 'unshare|setns')">
          <xsl:call-template name="emitNameSpace">
            <xsl:with-param name="_sact" select="$subact" />
          </xsl:call-template>
        </xsl:when>

        <!-- RESP_ events -->
        <xsl:when test="starts-with($act, 'resp_acct_lock')">
          <xsl:call-template name="emitAcctAction" />
        </xsl:when>

        <!-- Group Password change 
        
        20240511: Noting the message is
        grp_chauthok changing /etc/gshadow; group <group_name>, new password
        -->
        <xsl:when test="$act = 'grp_chauthtok' ">
          <xsl:call-template name="emitGrpPasswordChange" />
        </xsl:when>

        <!-- 20210915 Deal with a clone system call -->
        <xsl:when test="$act='syscall' and $subact = 'clone'">
          <xsl:call-template name="processEvent">
            <xsl:with-param name="processAction" select="'Execute'" />
            <xsl:with-param name="processType" select="'OS'" />
          </xsl:call-template>
        </xsl:when>

        <!-- 20211017 Deal with a mmap system call
        20230125 And mmap2 system call -->
        <xsl:when test="$act='syscall' and starts-with($subact,'mmap')">
          <xsl:call-template name="processEvent">
            <xsl:with-param name="processAction" select="'Call'" />
            <xsl:with-param name="processType" select="'OS'" />
          </xsl:call-template>
        </xsl:when>

        <!-- 20221221 Deal with a bpf system call -->
        <xsl:when test="$act='syscall' and $subact = 'bpf'">
          <xsl:call-template name="processEvent">
            <xsl:with-param name="processAction" select="'Call'" />
            <xsl:with-param name="processType" select="'OS'" />
          </xsl:call-template>
        </xsl:when>

        <!-- 20230125 Deal with a inofify_add_watch system call -->
        <xsl:when test="$act='syscall' and $subact = 'inotify_add_watch'">
          <xsl:call-template name="processEvent">
            <xsl:with-param name="processAction" select="'Call'" />
            <xsl:with-param name="processType" select="'OS'" />
          </xsl:call-template>
        </xsl:when>

        <!-- 20231206 Deal with a close system call -->
        <xsl:when test="$act='syscall' and $subact = 'close'">
          <xsl:call-template name="processEvent">
            <xsl:with-param name="processAction" select="'Call'" />
            <xsl:with-param name="processType" select="'OS'" />
          </xsl:call-template>
        </xsl:when>

        <!-- 
        Generic System Call
        Eventually we should stop the long OR test on subact and just test
        for a syscall and the fact there is only ONE data subelement (excluding proctitle) - ie the syscall
        -->

        <!--
        <xsl:when test="$act = 'syscall' and matches($subact, '^sem...$|semop|^msg...$|^shm...|^shmat|^ioctl|fork$|capset|setgroups|setfsgid|setfsuid|setregid|setreuid|clone|mmap|inotify_rm_watch|seek|fcntl|read|write|rt_sigaction')">
        -->
        <xsl:when test="$act = 'syscall' and count(data/*[not(self::proctitle)]) = 1">
          <xsl:call-template name="processEvent">
            <xsl:with-param name="processAction" select="'Call'" />
            <xsl:with-param name="processType" select="'OS'" />
          </xsl:call-template>
        </xsl:when>

        <!-- Cater for single system call with an avc element which probably implies failure -->
        <xsl:when test="$act = 'syscall' and count(data/syscall) = 1 and count(data/avc) >= 1">
          <xsl:call-template name="processEvent">
            <xsl:with-param name="processAction" select="'Call'" />
            <xsl:with-param name="processType" select="'OS'" />
          </xsl:call-template>
        </xsl:when>

        <!-- Software Update -->
        <xsl:when test="$act = 'software_update'">
          <xsl:call-template name="emitSoftwareUpdate" />
        </xsl:when>

        <!-- SELinux Labels -->
        <xsl:when test="$act = 'label_level_change'">
          <xsl:call-template name="emitLabelUpdate" />
        </xsl:when>

        <!-- BPF (audit_bpf is now 'bpf' 20210101 -->
        <xsl:when test="$act = 'bpf'">
          <xsl:call-template name="emitBPFUpdate" />
        </xsl:when>

        <!-- FANotify -->
        <xsl:when test="$act = 'fanotify'">
          <xsl:call-template name="processEvent">
            <xsl:with-param name="processAction" select="'Call'" />
            <xsl:with-param name="processType" select="'OS'" />
          </xsl:call-template>
        </xsl:when>

        <!-- stat -->
        <xsl:when test="$act = 'syscall' and contains($subact, 'stat')">
          <xsl:call-template name="emitFileStatus" />
        </xsl:when>

        <!-- -->
        <xsl:otherwise>
          <Unknown>
            <xsl:variable name="_myhost" select="translate(stroom:meta('MyHost'),'&quot;', '')" />
            <xsl:variable name="_myip" select="translate(stroom:meta('MyIPaddress'),'&quot;', '')" />
            <xsl:variable name="remoteHost" select="stroom:meta('RemoteHost')" />
            <xsl:variable name="Version" select="stroom:meta('Version')" />

            <!-- A current (as at 20210111) ausearch bug result in complete events being split into two events. We normally see this as an unknown event
            with $act values of 'proctitle, 'cwd' or 'path'. Don't warn on these -->
            <xsl:if test="not(matches($act, '^cwd|^proctitle|^path'))">
              <xsl:value-of select="stroom:log('WARN', concat('Stream Id: ', stroom:stream-id(), ' has an unknown event - ', $act, ':', $subact, ' T/E:', @time, '/', @serial, ' Host - MyHost:', $_myhost, ' MyIPaddress:', $_myip, ' RemoteHost:', $remoteHost, ' Version:', $Version))" />
            </xsl:if>
            <Data Name="AgentVersion" Value="{$Version}" />
            <Data Name="UnknownStreamRef" Value="{concat(stroom:source-id(), ':', stroom:part-no(), ':', stroom:record-no())}" />
            <xsl:call-template name="processIncidentals" />
            <xsl:call-template name="processPathIncidentals" />
          </Unknown>
        </xsl:otherwise>
      </xsl:choose>
    </EventDetail>
  </xsl:template>

  <!-- Accounting activities -->
  <xsl:template name="emitAcctAction">
    <xsl:choose>
      <xsl:when test="data/resp_acct_lock|data/resp_acct_lock_timed">
        <Authenticate>
          <Action>AccountLock</Action>
          <User>
            <xsl:call-template name="emitUserId">
              <xsl:with-param name="_u" select="./data//uid[last()]/@i" />
            </xsl:call-template>
          </User>
          <xsl:call-template name="emitOutcome" />
          <xsl:call-template name="processIncidentals" />
        </Authenticate>
      </xsl:when>
    </xsl:choose>
  </xsl:template>

  <!-- ProcessAcct -->
  <xsl:template name="emitAcct">
    <xsl:choose>
      <xsl:when test="data/path/item">
        <Create>
          <File>
            <Type>AccountingFile</Type>
            <xsl:call-template name="ownerModes">
              <xsl:with-param name="_item" select="data/path/item" />
            </xsl:call-template>
            <xsl:call-template name="genPath">
              <xsl:with-param name="_fn" select="data/path/item/name/@i" />
            </xsl:call-template>
          </File>
          <xsl:call-template name="emitOutcome" />
          <xsl:call-template name="processIncidentals" />

          <!-- 20221221: We want path details for this filesystem related activity -->
          <xsl:call-template name="processPathIncidentals" />
        </Create>
      </xsl:when>
      <xsl:otherwise>
        <Delete>
          <File>
            <Type>AccountingFile</Type>
          </File>
          <xsl:call-template name="emitOutcome" />
          <xsl:call-template name="processIncidentals" />

          <!-- 20221221: We want path details for this filesystem related activity -->
          <xsl:call-template name="processPathIncidentals" />
        </Delete>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <!-- Process TTY -->
  <xsl:template name="emitTTY">
    <Process>
      <Action>Execute</Action>
      <Type>Application</Type>
      <Command>
        <xsl:value-of select="distinct-values(data//comm/@i)" />
      </Command>
      <xsl:if test="exists(./data//pid/@i)">
        <ProcessId>
          <xsl:value-of select="distinct-values(./data//pid/@i)" />
        </ProcessId>
      </xsl:if>
      <xsl:call-template name="emitOutcome" />
      <xsl:call-template name="processIncidentals" />

      <!-- 20230304: Note that that we can have multiple data/tty elements, so we need
      to cater for this.
      In the case of capturingtext, in essence, we concatenate the ext, but we reverse a for-each
      so the last data/tty is the first component of captured text
      In the case of capturing device, we select the first data/tty as this will not change for
      multiple data/tty elements
      -->
      <Data Name="CapturedText">
        <xsl:attribute name="Value">
          <xsl:for-each select="./data/tty">
            <xsl:sort select="position()" data-type="number" order="descending" />
            <xsl:value-of select="normalize-space(./data/@i)" />
          </xsl:for-each>
        </xsl:attribute>
      </Data>
      <Data Name="CapturingDevice">
        <xsl:attribute name="Value">
          <xsl:value-of select="concat('Major/Minor: ', ./data/tty[1]/major/@i, '/', ./data/tty[1]/minor/@i)" />
        </xsl:attribute>
      </Data>
    </Process>
  </xsl:template>

  <!-- Process event -->
  <xsl:template name="processEvent">
    <xsl:param name="processAction" />
    <xsl:param name="processType" />
    <xsl:variable name="act" select="name(data/*[1])" />
    <xsl:variable name="cmd">
      <xsl:value-of select="distinct-values(data//comm/@i)" />
      <xsl:if test="data/user_cmd/cmd">
        <xsl:choose>
          <xsl:when test="contains(data/user_cmd/cmd/@i, ' ')">
            <xsl:value-of select="substring-before(data/user_cmd/cmd/@i, ' ')" />
          </xsl:when>
          <xsl:otherwise>
            <xsl:value-of select="data/user_cmd/cmd/@i" />
          </xsl:otherwise>
        </xsl:choose>
      </xsl:if>
    </xsl:variable>

    <!-- exe can be in data/{syscall,user} -->
    <xsl:variable name="exe" select="data//exe/@i" />
    <xsl:variable name="proctitle" select="data/proctitle/proctitle/@i" />
    <Process>
      <Action>
        <xsl:value-of select="$processAction" />
      </Action>
      <Type>
        <xsl:value-of select="$processType" />
      </Type>
      <Command>
        <xsl:choose>

          <!-- 20230601: A kernel action indicates the auditd process in addition to a daemon_ action -->
          <xsl:when test="matches($act, '^daemon_|kernel')">auditd</xsl:when>
          <xsl:when test="starts-with($act, 'service_')">
            <xsl:value-of select="data//unit/@i" />
            <xsl:text> </xsl:text>
            <xsl:value-of select="distinct-values(data//comm/@i)" />
          </xsl:when>

          <!-- Prefer a0 element of ausearch->aushape or the first a element for aushape if execve -->
          <xsl:when test="exists(./data/execve/a0)">
            <xsl:value-of select="./data/execve/a0/@i" />
          </xsl:when>
          <xsl:when test="exists(./data/execve/a[1])">
            <xsl:value-of select="./data/execve/a[1]/@i" />
          </xsl:when>
          <xsl:when test="string-length($cmd)>0">
            <xsl:value-of select="$cmd" />
          </xsl:when>
          <xsl:when test="string-length($exe)>0">
            <xsl:value-of select="$exe" />
          </xsl:when>

          <!-- 20221222 -->
          <xsl:when test="$act = 'user_tty'">
            <xsl:variable name="cmd" select="translate(data/user_tty/data/@i, '&#34;', '')" />
            <xsl:choose>
              <xsl:when test="contains($cmd, ' ')">
                <xsl:value-of select="substring-before($cmd, ' ')" />
              </xsl:when>
              <xsl:otherwise>
                <xsl:value-of select="$cmd" />
              </xsl:otherwise>
            </xsl:choose>
          </xsl:when>
        </xsl:choose>
      </Command>
      <xsl:if test="data/execve">
        <Arguments>

          <!-- For aushape we have a elements and the first is the command and the rest the arguements -->
          <xsl:for-each select="data/execve/a">
            <xsl:if test="position() > 1">
              <xsl:value-of select="concat(normalize-space(@i), ' ')" />
            </xsl:if>
          </xsl:for-each>

          <!-- For ausearch->aushape we have an elements and all elements are arguements -->

          <!-- 20240510 - lets make this more efficient as well as dropping the trailing space 
          <xsl:for-each select="data/execve/an">
          <xsl:value-of select="concat(normalize-space(@i), ' ')" />
          </xsl:for-each>
          -->

          <!-- 20240811 - RHEL6 occassionally has multiple EXECVE lines :-(, so cater for this
          
          node=centos6.fqdn.org type=PATH msg=audit(2024-08-10 15:45:30.960:171879) : item=2 name=(null) inode=655766 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:ld_so_t:s0 nametype=NORMAL 
          node=centos6.fqdn.org type=PATH msg=audit(2024-08-10 15:45:30.960:171879) : item=1 name=(null) inode=786434 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:shell_exec_t:s0 nametype=NORMAL 
          node=centos6.fqdn.org type=PATH msg=audit(2024-08-10 15:45:30.960:171879) : item=0 name=/usr/bin/gunzip inode=786460 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:bin_t:s0 nametype=NORMAL 
          node=centos6.fqdn.org type=CWD msg=audit(2024-08-10 15:45:30.960:171879) : cwd=/opt/stroom/auditd/queue 
          node=centos6.fqdn.org type=EXECVE msg=audit(2024-08-10 15:45:30.960:171879) : argc=3 a0=/bin/sh a1=/usr/bin/gunzip a2=-t 
          node=centos6.fqdn.org type=EXECVE msg=audit(2024-08-10 15:45:30.960:171879) : argc=4 a0=/bin/sh a1=/usr/bin/gunzip a2=-t a3=./auditdProcessed.8170.1723304719.gz 
          node=centos6.fqdn.org type=SYSCALL msg=audit(2024-08-10 15:45:30.960:171879) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x26e1040 a1=0x26ff420 a2=0x26fdd90 a3=0x7fffc20a2620 items=3 ppid=10041 pid=10042 auid=root uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=(none) ses=131 comm=gunzip exe=/bin/bash subj=system_u:system_r:system_cronjob_t:s0-s0:c0.c1023 key=cmds 
          -->
          <xsl:choose>
            <xsl:when test="count(data/execve/an) > 1">
              <xsl:for-each select="data/execve/an">
                <xsl:value-of select="concat(normalize-space(@i), ' ')" />
              </xsl:for-each>
            </xsl:when>
            <xsl:otherwise>
              <xsl:value-of select="string-join(normalize-space(data/execve/an/@i), ' ')" />
            </xsl:otherwise>
          </xsl:choose>

          <!-- For mounts
          Source device is @dev in last path element, Mount point is @name in last path element
          -->
          <xsl:if test="contains(./data/syscall/exe/@i, 'mount')">
            <xsl:variable name="_l" select="./data/syscall/items/@i" as="xs:integer" />
            <xsl:choose>
              <xsl:when test="$_l > 2">
                <xsl:value-of select="concat(./data/path/item[$_l]/name/@i, ' ', ./data/path/item[$_l - 1]/name/@i)" />
              </xsl:when>
              <xsl:when test="$_l > 1">
                <xsl:value-of select="./data/path/item[$_l]/name/@i" />
              </xsl:when>
            </xsl:choose>
          </xsl:if>
        </Arguments>
      </xsl:if>
      <xsl:if test="data/user_cmd/cmd and contains(data/user_cmd/cmd/@i, ' ')">
        <Arguments>
          <xsl:value-of select="substring-after(data/user_cmd/cmd/@i, ' ')" />
        </Arguments>
      </xsl:if>
      <xsl:if test="data/user_tty/data and contains(data/user_tty/data/@i, ' ')">
        <Arguments>
          <xsl:value-of select="translate(substring-after(data/user_tty/data/@i, ' '), '&#34;', '')" />
        </Arguments>
      </xsl:if>

      <!-- 20221221: For kill and ptrace use proctitle if present -->
      <xsl:if test="matches(data/syscall/syscall/@i,'ptrace|kill') and contains($proctitle, ' ')">
        <Arguments>
          <xsl:value-of select="substring-after($proctitle, ' ')" />
        </Arguments>
      </xsl:if>

      <!-- For mounts
      Source device is @dev in last path element, Mount point is @name in last path element
      -->
      <xsl:if test="contains(./data/syscall/syscall/@i, 'mount')">
        <Arguments>
          <xsl:variable name="_l" select="./data/syscall/items/@i" as="xs:integer" />
          <xsl:choose>
            <xsl:when test="$_l > 2">
              <xsl:value-of select="concat(./data/path/item[$_l]/name/@i, ' ', ./data/path/item[$_l - 1]/name/@i)" />
            </xsl:when>
            <xsl:when test="$_l > 1">
              <xsl:value-of select="./data/path/item[$_l]/name/@i" />
            </xsl:when>
          </xsl:choose>
        </Arguments>
      </xsl:if>
      <xsl:if test="exists(./data//pid/@i)">
        <ProcessId>

          <!-- 20230601: Better manage process id selection -->
          <xsl:choose>
            <xsl:when test="./data/syscall/pid">
              <xsl:value-of select="./data/syscall/pid/@i" />
            </xsl:when>
            <xsl:otherwise>
              <xsl:value-of select="distinct-values(./data//pid/@i)" />
            </xsl:otherwise>
          </xsl:choose>
        </ProcessId>
      </xsl:if>
      <xsl:if test="data/syscall/syscall/@i = 'clone' and data/syscall/success/@i = 'yes'">
        <ThreadId>
          <xsl:value-of select="data/syscall/exit/@i" />
        </ThreadId>
      </xsl:if>
      <xsl:if test="data//key/@i|data/seccomp/code/@i">
        <Rule>

          <!-- Sometimes keys are repeated 20221219 -->
          <xsl:value-of select="distinct-values(data//key/@i)" />
          <xsl:value-of select="data/seccomp/code/@i" />
        </Rule>
      </xsl:if>

      <!-- -->
      <xsl:call-template name="emitOutcome" />

      <!-- 20221221: For kill and other syscalls that operate on other processes -->

      <!-- Emit the object acted upon as space separated key=value pairs, escaping '=' in the value -->
      <xsl:if test="data/obj_pid">
        <xsl:for-each select="data/obj_pid">
          <Data Name="ObjectActedUpon">
            <xsl:attribute name="Value">
              <xsl:for-each select="*">
                <xsl:choose>
                  <xsl:when test="position() = 1">
                    <xsl:value-of select="concat(name(), '=', replace(@i,'(=|\\)','\\$1'))" />
                  </xsl:when>
                  <xsl:otherwise>
                    <xsl:value-of select="concat(' ', name(), '=', replace(@i,'(=|\\)','\\$1'))" />
                  </xsl:otherwise>
                </xsl:choose>
              </xsl:for-each>
            </xsl:attribute>
          </Data>
        </xsl:for-each>
      </xsl:if>

      <!-- 20221220: Format sig=%ld arch=%x syscall=%ld compat=%d ip=0x%lx code=0x%x -->
      <xsl:if test="data/seccomp">
        <Data Name='SecureComputingState'>
          <xsl:attribute name="Value">
            <xsl:value-of select="concat('Signal: ', data/seccomp/sig/@i, ' Syscall: ', data/seccomp/syscall/@i, ' IsCompatSyscall:', data/seccomp/syscall/@i, ' Action: ', data/seccomp/code/@i, ' IP:', data/seccomp/ip/@i )" />
          </xsl:attribute>
        </Data>
      </xsl:if>

      <!-- 220221221: BPF record may appear with a syscall event, so note it -->
      <xsl:if test="data/bpf">
        <Data Name="BPF_Action" Value="{data/bpf/op/@i}" />
        <Data Name="BPF_ProgramId" Value="{data/bpf/progid/@i|data/bpf/prog-id/@i}" />
      </xsl:if>

      <!-- 20221220: User message - display message text -->
      <xsl:if test="data/user/text">
        <Data Name="SentMessageText" Value="{data/user/text/@i}" />
      </xsl:if>

      <!-- 20211017: Some calls - clone - can have multiple netfilter_cfg entries -->
      <xsl:for-each select="data/netfilter_cfg">
        <Data Name="Netfilter" Value="{concat('Family: ', family/@i, ' Table: ', table/@i, ' Entries: ', entries/@i)}" />
      </xsl:for-each>

      <!-- 20211017: mmap element -->
      <xsl:if test="data/mmap">
        <Data Name="mmap_flags" Value="{data/mmap/flags/@i}" />
        <Data Name="mmap_fd" Value="{data/mmap/fd/@i}" />
      </xsl:if>

      <!-- 20221219: fanotify extensions resp=2 fan_type=1 fan_info=3137 subj_trust=3 obj_trust=5 .. -->
      <xsl:if test="data/fanotify">

        <!-- Cater for multiples -->
        <xsl:for-each select="data/fanotify">
          <Data Name="fanotify_resp" Value="{resp/@i}" />
          <xsl:if test="fan_type">
            <Data Name="fanotify_info" Value="{concat('fan_type:', fan_type/@i, ' fan_info:', fan_info/@i, ' subj_trust:',  subj_trust/@i, ' obj_trust:',  obj_trust/@i)}" />
          </xsl:if>
        </xsl:for-each>
      </xsl:if>

      <!-- Find other bits and pieces -->
      <xsl:call-template name="processIncidentals" />

      <!-- Some execve's contain paths -->
      <xsl:call-template name="processPathIncidentals" />
    </Process>
  </xsl:template>

  <!-- emitDelete -->
  <xsl:template name="emitDelete">
    <Delete>
      <xsl:variable name="_ditems" select="./data/path/item[last()]" />
      <xsl:variable name="_objT">

        <!-- We are either a directory (aka Folder) or a File -->
        <xsl:choose>
          <xsl:when test="matches($_ditems/mode/@i,'^dir')">Folder</xsl:when>
          <xsl:otherwise>File</xsl:otherwise>
        </xsl:choose>
      </xsl:variable>
      <xsl:element name="{$_objT}">
        <xsl:call-template name="ownerModes">
          <xsl:with-param name="_item" select="$_ditems" />
        </xsl:call-template>
        <xsl:call-template name="genPath">
          <xsl:with-param name="_fn" select="$_ditems/name/@i" />
        </xsl:call-template>
      </xsl:element>
      <xsl:call-template name="emitOutcome" />
      <xsl:call-template name="processIncidentals" />

      <!-- 20221221: We want path details for this filesystem related activity -->
      <xsl:call-template name="processPathIncidentals" />
    </Delete>
  </xsl:template>

  <!-- emitMkdir -->
  <xsl:template name="emitMkdir">
    <Create>
      <xsl:variable name="_ditems" select="./data/path/item[last()]" />
      <xsl:variable name="_objT">

        <!-- We are either a directory (aka Folder) or a File -->
        <xsl:choose>
          <xsl:when test="matches($_ditems/mode/@i,'^dir')">Folder</xsl:when>
          <xsl:otherwise>File</xsl:otherwise>
        </xsl:choose>
      </xsl:variable>
      <xsl:element name="{$_objT}">
        <xsl:call-template name="ownerModes">
          <xsl:with-param name="_item" select="$_ditems" />
        </xsl:call-template>
        <xsl:call-template name="genPath">
          <xsl:with-param name="_fn" select="$_ditems/name/@i" />
        </xsl:call-template>
      </xsl:element>
      <xsl:call-template name="emitOutcome" />
      <xsl:call-template name="processIncidentals" />

      <!-- 20221221: We want path details for this filesystem related activity -->
      <xsl:call-template name="processPathIncidentals" />
    </Create>
  </xsl:template>

  <!-- emitMkdir -->
  <xsl:template name="emitCreate">
    <Create>
      <xsl:variable name="_ditems" select="./data/path/item[last()]" />
      <xsl:variable name="_objT">

        <!-- We are either a directory (aka Folder) or a File -->
        <xsl:choose>
          <xsl:when test="matches($_ditems/mode/@i,'^dir')">Folder</xsl:when>
          <xsl:otherwise>File</xsl:otherwise>
        </xsl:choose>
      </xsl:variable>
      <xsl:element name="{$_objT}">
        <xsl:call-template name="ownerModes">
          <xsl:with-param name="_item" select="$_ditems" />
        </xsl:call-template>
        <xsl:call-template name="genPath">
          <xsl:with-param name="_fn" select="$_ditems/name/@i" />
        </xsl:call-template>
      </xsl:element>
      <xsl:call-template name="emitOutcome" />
      <xsl:call-template name="processIncidentals" />

      <!-- 20221221: We want path details for this filesystem related activity -->
      <xsl:call-template name="processPathIncidentals" />
    </Create>
  </xsl:template>

  <!-- Modules -->
  <xsl:template name="emitDeleteModule">
    <Description>Unload a kernel module</Description>
    <Delete>
      <Object>
        <Type>Module</Type>

        <!-- Get the name from the kern_module/name value else if protitle exists and has an argument, get the argument -->
        <xsl:choose>
          <xsl:when test="data/kern_module/name">
            <Name>
              <xsl:value-of select="data/kern_module/name/@i" />
            </Name>
          </xsl:when>
          <xsl:when test="data/proctitle and contains(data/proctitle/proctitle/@i, ' ')">
            <Name>
              <xsl:value-of select="substring-after(data/proctitle/proctitle/@i, ' ')" />
            </Name>
          </xsl:when>
        </xsl:choose>
      </Object>
      <xsl:call-template name="emitOutcome" />
      <xsl:call-template name="processIncidentals" />
    </Delete>
  </xsl:template>
  <xsl:template name="emitCreateModule">
    <Description>Load a kernel module</Description>
    <Create>
      <Object>
        <Type>Module</Type>

        <!-- Get the name from the kern_module/name value else if protitle exists and has an argument, get the argument -->
        <xsl:choose>
          <xsl:when test="data/kern_module/name">
            <Name>
              <xsl:value-of select="data/kern_module/name/@i" />
            </Name>
          </xsl:when>
          <xsl:when test="data/proctitle and contains(data/proctitle/proctitle/@i, ' ')">
            <Name>
              <xsl:value-of select="substring-after(data/proctitle/proctitle/@i, ' ')" />
            </Name>
          </xsl:when>
        </xsl:choose>
      </Object>
      <xsl:call-template name="emitOutcome" />
      <xsl:call-template name="processIncidentals" />

      <!-- 20221221: Add path incidentals as we can track inode if needed -->
      <xsl:call-template name="processPathIncidentals" />
    </Create>
  </xsl:template>

  <!-- emitMove -->
  <xsl:template name="emitMove">

    <!-- Move are
    If last path/item == 4, then 
    mv path[0]/path[2] path[1]/path[4]
    If last path/item == 3 then
    mv path[0]/path[2] path[1]/path[3]
    note if path[2][@name] == '(null)' then source filename is same as destination basename
    Note we strip the source and destination files of the directory component and any trailing slashes
    so we can rebuild the filepath
    TODO: Fix directories on small number of items - ie do concat when forming variable based on $_nitems
    -->
    <Move>
      <xsl:variable name="_dobj" select="replace(replace(./data/path/item[last()]/name/@i,'/$',''),'.*/','')" />
      <xsl:variable name="_ditem" select="./data/path/item[last()]" />
      <xsl:variable name="_nitems" select="./data/syscall/items/@i" as="xs:integer" />
      <xsl:variable name="_sitem" select="if ($_nitems eq 2) then ./data/path/item[1] else ./data/path/item[3]" />
      <xsl:variable name="_sobj">
        <xsl:choose>
          <xsl:when test="$_sitem/name/@i='(null)'">
            <xsl:value-of select="$_dobj" />
          </xsl:when>
          <xsl:otherwise>
            <xsl:value-of select="replace(replace($_sitem/name/@i,'/$',''),'.*/','')" />
          </xsl:otherwise>
        </xsl:choose>
      </xsl:variable>

      <!-- We are either a directory (aka Folder) or a File -->
      <xsl:variable name="_objT">
        <xsl:choose>
          <xsl:when test="matches(./data/path/item[last()]/mode/@i,'^dir')">Folder</xsl:when>
          <xsl:otherwise>File</xsl:otherwise>
        </xsl:choose>
      </xsl:variable>
      <Source>
        <xsl:element name="{$_objT}">
          <xsl:call-template name="ownerModes">
            <xsl:with-param name="_item" select="$_sitem" />
          </xsl:call-template>
          <xsl:variable name="_fp">
            <xsl:choose>
              <xsl:when test="$_nitems eq 2">
                <xsl:value-of select="./data/path/item[1]/name/@i" />
              </xsl:when>
              <xsl:otherwise>
                <xsl:value-of select="concat(./data/path/item[1]/name/@i, '/', $_sobj)" />
              </xsl:otherwise>
            </xsl:choose>
          </xsl:variable>
          <xsl:call-template name="genPath">
            <xsl:with-param name="_fn" select="$_fp" />
          </xsl:call-template>
        </xsl:element>
      </Source>
      <Destination>
        <xsl:element name="{$_objT}">
          <xsl:call-template name="ownerModes">
            <xsl:with-param name="_item" select="$_ditem" />
          </xsl:call-template>
          <xsl:variable name="_fp">
            <xsl:choose>
              <xsl:when test="$_nitems eq 2">
                <xsl:value-of select="./data/path/item[last()]/name/@i" />
              </xsl:when>
              <xsl:otherwise>
                <xsl:value-of select="concat(./data/path/item[2]/name/@i, '/', $_dobj)" />
              </xsl:otherwise>
            </xsl:choose>
          </xsl:variable>
          <xsl:call-template name="genPath">
            <xsl:with-param name="_fn" select="$_fp" />
          </xsl:call-template>
        </xsl:element>
      </Destination>
      <xsl:call-template name="emitOutcome" />
      <xsl:call-template name="processIncidentals" />

      <!-- 20221221: We want path details for this filesystem related activity -->
      <xsl:call-template name="processPathIncidentals" />
    </Move>
  </xsl:template>

  <!-- emitLink -->
  <xsl:template name="emitLink">

    <!-- Link|Symlink are
    path[0] = source file
    path[1] = source directory
    path[2] = destination file
    If we are a symlink then the source item details
    Note we strip the source and destination files of the directory component and any trailing slashes
    so we can rebuild the filepath
    TODO: Fix directories on small number of items - ie do concat when forming variable based on $_nitems
    -->
    <Copy>
      <xsl:variable name="_dobj" select="replace(replace(./data/path/item[last()]/name/@i,'/$',''),'.*/','')" />
      <xsl:variable name="_ditem" select="./data/path/item[last()]" />
      <xsl:variable name="_subact" select="./data/syscall/syscall/@i" />
      <xsl:variable name="_sitem" select="if ($_subact = 'symlink') then ./data/path/item[2] else ./data/path/item[0]" />

      <!-- We are either a directory (aka Folder) or a File -->
      <xsl:variable name="_objT">
        <xsl:choose>
          <xsl:when test="matches(./data/path/item[last()]/mode/@i,'^dir')">Folder</xsl:when>
          <xsl:otherwise>File</xsl:otherwise>
        </xsl:choose>
      </xsl:variable>
      <Source>
        <xsl:element name="{$_objT}">
          <xsl:call-template name="ownerModes">
            <xsl:with-param name="_item" select="$_sitem" />
          </xsl:call-template>
          <xsl:variable name="_fp">
            <xsl:value-of select="concat(./data/path/item[2]/name/@i, '/', ./data/path/item[1]/name/@i)" />
          </xsl:variable>
          <xsl:call-template name="genPath">
            <xsl:with-param name="_fn" select="$_fp" />
          </xsl:call-template>
        </xsl:element>
      </Source>
      <Destination>
        <xsl:element name="{$_objT}">
          <xsl:call-template name="ownerModes">
            <xsl:with-param name="_item" select="$_ditem" />
          </xsl:call-template>
          <xsl:variable name="_fp">
            <xsl:value-of select="./data/path/item[last()]/name/@i" />
          </xsl:variable>
          <xsl:call-template name="genPath">
            <xsl:with-param name="_fn" select="$_fp" />
          </xsl:call-template>
        </xsl:element>
      </Destination>
      <xsl:call-template name="emitOutcome" />
      <xsl:call-template name="processIncidentals" />

      <!-- 20221221: We want path details for this filesystem related activity -->
      <xsl:call-template name="processPathIncidentals" />
    </Copy>
  </xsl:template>

  <!-- emitChown -->
  <xsl:template name="emitChown">
    <Update>

      <!--
      For multiple path/item elements, the first item is the old reference and the second is the new reference
      If we only have one path/item element, then item[1] == item[last()] (20201229)
      -->
      <xsl:variable name="_obj" select="./data/path/item/name/@i" />
      <xsl:variable name="_objT">

        <!-- We are either a directory (aka Folder) or a File -->
        <xsl:choose>
          <xsl:when test="matches(./data/path/item[last()]/mode/@i,'^dir')">Folder</xsl:when>
          <xsl:otherwise>File</xsl:otherwise>
        </xsl:choose>
      </xsl:variable>

      <!--
      Sometimes we don't have a path .. this is typically avc denied activity
      We also note that if the chown returned a 'not such file or directory' the path
      will have limited content. We test for the content need in the <Before> element (20201229)
      -->
      <xsl:if test="./data/path and data/path/item[1]/ouid/@i and data/path/item[1]/ogid/@i and data/path/item[1]/name/@i">
        <Before>
          <xsl:element name="{$_objT}">
            <Permissions>
              <Permission>
                <User>
                  <xsl:call-template name="emitUserId">
                    <xsl:with-param name="_u" select="./data/path/item[1]/ouid/@i" />
                  </xsl:call-template>
                </User>
              </Permission>
              <Permission>
                <Group>
                  <Id>
                    <xsl:value-of select="./data/path/item[1]/ogid/@i" />
                  </Id>
                </Group>
              </Permission>
            </Permissions>
            <xsl:call-template name="genPath">
              <xsl:with-param name="_fn" select="./data/path/item[1]/name/@i" />
            </xsl:call-template>
          </xsl:element>
        </Before>
      </xsl:if>
      <After>
        <xsl:element name="{$_objT}">
          <Permissions>
            <Permission>
              <User>

                <!-- 20240922: Use emitUserId function for User/Id value as it will set User/Type as required -->
                <xsl:variable name="_id">
                  <xsl:choose>

                    <!-- 20221222: fchownat uses a2 as the new uid, the rest use a1 -->
                    <xsl:when test="data/syscall/syscall/@i = 'fchownat' or starts-with(./data/syscall/a0/@i, '0xff')">
                      <xsl:call-template name="chownArgs">
                        <xsl:with-param name="_oid" select="./data/path/item[last()]/ouid/@i" />
                        <xsl:with-param name="_nid" select="./data/syscall/a2/@i" />
                      </xsl:call-template>
                    </xsl:when>
                    <xsl:otherwise>
                      <xsl:call-template name="chownArgs">
                        <xsl:with-param name="_oid" select="./data/path/item[last()]/ouid/@i" />
                        <xsl:with-param name="_nid" select="./data/syscall/a1/@i" />
                      </xsl:call-template>
                    </xsl:otherwise>
                  </xsl:choose>
                </xsl:variable>
                <xsl:call-template name="emitUserId">
                  <xsl:with-param name="_u" select="$_id" />
                </xsl:call-template>
              </User>
            </Permission>
            <Permission>
              <Group>
                <Id>
                  <xsl:choose>

                    <!-- 20221222: fchownat uses a3 as the new gid, the rest use a2 -->
                    <xsl:when test="data/syscall/syscall/@i = 'fchownat' or starts-with(./data/syscall/a0/@i, '0xff')">
                      <xsl:call-template name="chownArgs">
                        <xsl:with-param name="_oid" select="./data/path/item[last()]/ogid/@i" />
                        <xsl:with-param name="_nid" select="./data/syscall/a3/@i" />
                      </xsl:call-template>
                    </xsl:when>
                    <xsl:otherwise>
                      <xsl:call-template name="chownArgs">
                        <xsl:with-param name="_oid" select="./data/path/item[last()]/ogid/@i" />
                        <xsl:with-param name="_nid" select="./data/syscall/a2/@i" />
                      </xsl:call-template>
                    </xsl:otherwise>
                  </xsl:choose>
                </Id>
              </Group>
            </Permission>
          </Permissions>
          <xsl:if test="./data/path">
            <xsl:call-template name="genPath">
              <xsl:with-param name="_fn" select="./data/path/item[last()]/name/@i" />
            </xsl:call-template>
          </xsl:if>
        </xsl:element>
      </After>
      <xsl:call-template name="emitOutcome" />
      <xsl:call-template name="processIncidentals" />

      <!-- 20221221: We want path details for this filesystem related activity -->
      <xsl:call-template name="processPathIncidentals" />
    </Update>
  </xsl:template>

  <!-- 
  chown|chgrp args for the new values.
  If new uid/gid not explicitly given (e.g. 'chgrp group file' or 'chown user file'), 
  the id value gets populated as 'ffffffff' (or 'unset') and hence this indicates this id does not change 
  -->
  <xsl:template name="chownArgs">
    <xsl:param name="_oid" />
    <xsl:param name="_nid" />
    <xsl:choose>
      <xsl:when test="$_nid='ffffffff' or $_nid='0xffffffff' or $_nid='unset'">
        <xsl:value-of select="$_oid" />
      </xsl:when>
      <xsl:when test="not(starts-with($_nid, '0x'))">
        <xsl:value-of select="$_nid" />
      </xsl:when>
      <xsl:otherwise>

        <!-- Note the id's start with 0x -->
        <xsl:value-of select="stroom:hex-to-dec(substring($_nid,3))" />
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <!-- emitChmod -->
  <xsl:template name="emitChmod">

    <!-- TODO: One can have multiple path/item elements
    20200119 - changed _citems to select the first [1] path/item to identify what is being chmod'ed
    Performing test
    -->
    <Update>
      <xsl:variable name="_citems" select="./data/path/item[1]" />
      <xsl:variable name="oMode" select="substring-after($_citems/mode/@i, ',')" />

      <!-- We are either a directory (aka Folder) or a File -->
      <xsl:variable name="_objT">
        <xsl:choose>
          <xsl:when test="matches($_citems/mode/@i,'^dir')">Folder</xsl:when>
          <xsl:otherwise>File</xsl:otherwise>
        </xsl:choose>
      </xsl:variable>
      <Before>
        <xsl:element name="{$_objT}">
          <Permissions>
            <Permission>

              <!-- In the case where we can't find the user or group (e.g. no such file or directory), we use an '_unknown_' user or group -->
              <xsl:variable name="_id">
                <xsl:choose>
                  <xsl:when test="$_citems/ouid/@i">
                    <xsl:value-of select="$_citems/ouid/@i" />
                  </xsl:when>
                  <xsl:otherwise>_unknown_</xsl:otherwise>
                </xsl:choose>
              </xsl:variable>
              <User>
                <xsl:call-template name="emitUserId">
                  <xsl:with-param name="_u" select="$_id" />
                </xsl:call-template>
              </User>
              <xsl:call-template name="fileModes">
                <xsl:with-param name="mode" select="substring($oMode,1,1)" />
              </xsl:call-template>
            </Permission>
            <Permission>

              <!-- In the case where we can't find the user or group (e.g. no such file or directory), we use an '_unknown_' user or group -->
              <xsl:variable name="_id">
                <xsl:choose>
                  <xsl:when test="$_citems/ogid/@i">
                    <xsl:value-of select="$_citems/ogid/@i" />
                  </xsl:when>
                  <xsl:otherwise>_unknown_</xsl:otherwise>
                </xsl:choose>
              </xsl:variable>
              <Group>
                <Id>
                  <xsl:value-of select="$_id" />
                </Id>
              </Group>
              <xsl:call-template name="fileModes">
                <xsl:with-param name="mode" select="substring($oMode,2,1)" />
              </xsl:call-template>
            </Permission>
            <Permission>
              <User>
                <Type>NPE</Type>
                <Id>Other</Id>
              </User>
              <xsl:call-template name="fileModes">
                <xsl:with-param name="mode" select="substring($oMode,3,1)" />
              </xsl:call-template>
            </Permission>
          </Permissions>
          <xsl:call-template name="genPath">
            <xsl:with-param name="_fn" select="$_citems/name/@i" />
          </xsl:call-template>
        </xsl:element>
      </Before>
      <After>
        <xsl:variable name="amode">
          <xsl:choose>

            <!-- 20221222: fchmodat uses a2 as the new mode, the rest use a1 -->
            <xsl:when test="data/syscall/syscall/@i = 'fchmodat' or starts-with(./data/syscall/a0/@i, '0xff')">
              <xsl:value-of select="replace(./data/syscall/a2/@i,'[^0-9]','')" />
            </xsl:when>
            <xsl:otherwise>
              <xsl:value-of select="replace(./data/syscall/a1/@i,'[^0-9]','')" />
            </xsl:otherwise>
          </xsl:choose>
        </xsl:variable>
        <xsl:element name="{$_objT}">
          <Permissions>
            <Permission>

              <!-- In the case where we can't find the user or group (e.g. no such file or directory), we use an '_unknown_' user or group -->
              <xsl:variable name="_id">
                <xsl:choose>
                  <xsl:when test="$_citems/ouid/@i">
                    <xsl:value-of select="$_citems/ouid/@i" />
                  </xsl:when>
                  <xsl:otherwise>_unknown_</xsl:otherwise>
                </xsl:choose>
              </xsl:variable>
              <User>
                <xsl:call-template name="emitUserId">
                  <xsl:with-param name="_u" select="$_id" />
                </xsl:call-template>
              </User>
              <xsl:call-template name="fileModes">
                <xsl:with-param name="mode" select="substring($amode,2,1)" />
              </xsl:call-template>
            </Permission>
            <Permission>

              <!-- In the case where we can't find the user or group (e.g. no such file or directory), we use an '_unknown_' user or group -->
              <xsl:variable name="_id">
                <xsl:choose>
                  <xsl:when test="$_citems/ogid/@i">
                    <xsl:value-of select="$_citems/ogid/@i" />
                  </xsl:when>
                  <xsl:otherwise>_unknown_</xsl:otherwise>
                </xsl:choose>
              </xsl:variable>
              <Group>
                <Id>
                  <xsl:value-of select="$_id" />
                </Id>
              </Group>
              <xsl:call-template name="fileModes">
                <xsl:with-param name="mode" select="substring($amode,3,1)" />
              </xsl:call-template>
            </Permission>
            <Permission>
              <User>
                <Type>NPE</Type>
                <Id>Other</Id>
              </User>
              <xsl:call-template name="fileModes">
                <xsl:with-param name="mode" select="substring($amode,4,1)" />
              </xsl:call-template>
            </Permission>
          </Permissions>
          <xsl:call-template name="genPath">
            <xsl:with-param name="_fn" select="$_citems/name/@i" />
          </xsl:call-template>
        </xsl:element>
      </After>
      <xsl:call-template name="emitOutcome" />
      <xsl:call-template name="processIncidentals" />

      <!-- 20221221: We want path details for this filesystem related activity -->
      <xsl:call-template name="processPathIncidentals" />
    </Update>
  </xsl:template>

  <!-- emitOpen -->
  <xsl:template name="emitOpen">

    <!-- The filename and mode are in the last path item -->
    <xsl:variable name="_obj" select="./data/path/item[last()]/name/@i" />

    <!-- 20221222: The mode attribute can have multiple strings before the mode as per file,suid,755 so get the last value in a csv list -->
    <xsl:variable name="fMode" select="tokenize(./data/path/item[last()]/mode/@i, ',')[last()]" />
    <xsl:variable name="_objT">

      <!-- We are either a directory (aka Folder) or a File -->
      <xsl:choose>
        <xsl:when test="matches(./data/path/item[last()]/mode/@i,'^dir')">Folder</xsl:when>
        <xsl:otherwise>File</xsl:otherwise>
      </xsl:choose>
    </xsl:variable>
    <xsl:choose>

      <!-- 20221221: openat, open_by_handle_at have their flags in a2 -->
      <xsl:when test="matches(./data/syscall/a1/@i, 'O_RDONLY|R_OK') or matches(./data/syscall/syscall/@i,'readlink|access') or ./data/openat2 or matches(./data/syscall/a2/@i, 'O_RDONLY|R_OK')">
        <View>
          <xsl:element name="{$_objT}">
            <Permissions>
              <Permission>
                <xsl:variable name="_id">
                  <xsl:choose>
                    <xsl:when test="./data/path/item[last()]/ouid/@i">
                      <xsl:value-of select="./data/path/item[last()]/ouid/@i" />
                    </xsl:when>
                    <xsl:otherwise>_unknown_</xsl:otherwise>
                  </xsl:choose>
                </xsl:variable>
                <User>
                  <xsl:call-template name="emitUserId">
                    <xsl:with-param name="_u" select="$_id" />
                  </xsl:call-template>
                </User>
                <xsl:call-template name="fileModes">
                  <xsl:with-param name="mode" select="substring($fMode,1,1)" />
                </xsl:call-template>
              </Permission>
              <Permission>
                <xsl:variable name="_id">
                  <xsl:choose>
                    <xsl:when test="./data/path/item[last()]/ogid/@i">
                      <xsl:value-of select="./data/path/item[last()]/ogid/@i" />
                    </xsl:when>
                    <xsl:otherwise>_unknown_</xsl:otherwise>
                  </xsl:choose>
                </xsl:variable>
                <Group>
                  <Id>
                    <xsl:value-of select="$_id" />
                  </Id>
                </Group>
                <xsl:call-template name="fileModes">
                  <xsl:with-param name="mode" select="substring($fMode,2,1)" />
                </xsl:call-template>
              </Permission>
              <Permission>
                <User>
                  <Type>NPE</Type>
                  <Id>Other</Id>
                </User>
                <xsl:call-template name="fileModes">
                  <xsl:with-param name="mode" select="substring($fMode,3,1)" />
                </xsl:call-template>
              </Permission>
            </Permissions>
            <xsl:call-template name="genPath">
              <xsl:with-param name="_fn" select="./data/path/item[last()]/name/@i" />
            </xsl:call-template>
            <Data Name="OpenMode">
              <xsl:attribute name="Value">
                <xsl:choose>
                  <xsl:when test="./data/openat2">
                    <xsl:value-of select="concat('oflag=', ./data/openat2/oflag/@i, ' mode=', ./data/openat2/mode/@i, ' resolve=',./data/openat2/resolve/@i)" />
                  </xsl:when>

                  <!-- 20221221: openat/accessat/open_by_handle_at have flags at a2 -->
                  <xsl:when test="matches(data/syscall/syscall/@i,'openat|accessat|open_by_handle_at')">
                    <xsl:value-of select="./data/syscall/a2/@i" />
                  </xsl:when>
                  <xsl:otherwise>
                    <xsl:value-of select="./data/syscall/a1/@i" />
                  </xsl:otherwise>
                </xsl:choose>
              </xsl:attribute>
            </Data>
            <Data Name="Device">
              <xsl:attribute name="Value" select="./data/path/item[last()]/dev/@i" />
            </Data>
          </xsl:element>
          <xsl:call-template name="emitOutcome" />
          <xsl:call-template name="processIncidentals" />

          <!-- 20221221: We want path details for this filesystem related activity -->
          <xsl:call-template name="processPathIncidentals" />
        </View>
      </xsl:when>
      <xsl:otherwise>
        <Update>
          <After>
            <xsl:element name="{$_objT}">
              <Permissions>
                <Permission>

                  <!-- In the case where we can't find the user or group (e.g. no such file or directory), we use an '_unknown_' user or group -->
                  <xsl:variable name="_id">
                    <xsl:choose>
                      <xsl:when test="./data/path/item[last()]/ouid/@i">
                        <xsl:value-of select="./data/path/item[last()]/ouid/@i" />
                      </xsl:when>
                      <xsl:otherwise>_unknown_</xsl:otherwise>
                    </xsl:choose>
                  </xsl:variable>
                  <User>
                    <xsl:call-template name="emitUserId">
                      <xsl:with-param name="_u" select="$_id" />
                    </xsl:call-template>
                  </User>
                  <xsl:call-template name="fileModes">
                    <xsl:with-param name="mode" select="substring($fMode,1,1)" />
                  </xsl:call-template>
                </Permission>
                <Permission>

                  <!-- In the case where we can't find the user or group (e.g. no such file or directory), we use an '_unknown_' user or group -->
                  <xsl:variable name="_id">
                    <xsl:choose>
                      <xsl:when test="./data/path/item[last()]/ogid/@i">
                        <xsl:value-of select="./data/path/item[last()]/ogid/@i" />
                      </xsl:when>
                      <xsl:otherwise>_unknown_</xsl:otherwise>
                    </xsl:choose>
                  </xsl:variable>
                  <Group>
                    <Id>
                      <xsl:value-of select="$_id" />
                    </Id>
                  </Group>
                  <xsl:call-template name="fileModes">
                    <xsl:with-param name="mode" select="substring($fMode,2,1)" />
                  </xsl:call-template>
                </Permission>
                <Permission>
                  <User>
                    <Type>NPE</Type>
                    <Id>Other</Id>
                  </User>
                  <xsl:call-template name="fileModes">
                    <xsl:with-param name="mode" select="substring($fMode,3,1)" />
                  </xsl:call-template>
                </Permission>
              </Permissions>
              <xsl:call-template name="genPath">
                <xsl:with-param name="_fn" select="./data/path/item[last()]/name/@i" />
              </xsl:call-template>

              <!-- 20221221: Redo openmode -->
              <Data Name="OpenMode">
                <xsl:attribute name="Value">
                  <xsl:choose>
                    <xsl:when test="./data/openat2">
                      <xsl:value-of select="concat('oflag=', ./data/openat2/oflag/@i, ' mode=', ./data/openat2/mode/@i, ' resolve=',./data/openat2/resolve/@i)" />
                    </xsl:when>

                    <!-- 20221221: openat/accessat/open_by_handle_at have flags at a2 -->
                    <xsl:when test="matches(data/syscall/syscall/@i,'openat|accessat|open_by_handle_at')">
                      <xsl:value-of select="./data/syscall/a2/@i" />
                    </xsl:when>
                    <xsl:otherwise>
                      <xsl:value-of select="./data/syscall/a1/@i" />
                    </xsl:otherwise>
                  </xsl:choose>
                </xsl:attribute>
              </Data>
              <Data Name="Device">
                <xsl:attribute name="Value" select="./data/path/item[last()]/dev/@i" />
              </Data>
            </xsl:element>
          </After>
          <xsl:call-template name="emitOutcome" />
          <xsl:call-template name="processIncidentals" />

          <!-- 20221221: We want path details for this filesystem related activity -->
          <xsl:call-template name="processPathIncidentals" />
        </Update>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <!-- emitSetxattr -->
  <xsl:template name="emitSetxattr">
    <Update>
      <xsl:variable name="_obj" select="./data/path/item/name/@i" />

      <!-- 20221222: The mode attribute can have multiple strings before the mode as per file,suid,755 so get the last value in a csv list -->
      <xsl:variable name="oMode" select="tokenize(./data/path/item/mode/@i, ',')[last()]" />

      <!--
      <xsl:variable name="oMode" select="substring-after(./data/path/item/mode/@i, ',')" />
      -->
      <xsl:variable name="_objT">

        <!-- We are either a directory (aka Folder) or a File -->
        <xsl:choose>
          <xsl:when test="matches(./data/path/item/mode/@i,'^dir')">Folder</xsl:when>
          <xsl:otherwise>File</xsl:otherwise>
        </xsl:choose>
      </xsl:variable>
      <After>
        <xsl:element name="{$_objT}">
          <Permissions>
            <Permission>

              <!-- In the case where we can't find the user or group (e.g. no such file or directory), we use an '_unknown_' user or group -->
              <xsl:variable name="_id">
                <xsl:choose>
                  <xsl:when test="./data/path/item/ouid/@i">
                    <xsl:value-of select="./data/path/item/ouid/@i" />
                  </xsl:when>
                  <xsl:otherwise>_unknown_</xsl:otherwise>
                </xsl:choose>
              </xsl:variable>
              <User>
                <xsl:call-template name="emitUserId">
                  <xsl:with-param name="_u" select="$_id" />
                </xsl:call-template>
              </User>
              <xsl:call-template name="fileModes">
                <xsl:with-param name="mode" select="substring($oMode,1,1)" />
              </xsl:call-template>
            </Permission>
            <Permission>

              <!-- In the case where we can't find the user or group (e.g. no such file or directory), we use an '_unknown_' user or group -->
              <xsl:variable name="_id">
                <xsl:choose>
                  <xsl:when test="./data/path/item/ogid/@i">
                    <xsl:value-of select="./data/path/item/ogid/@i" />
                  </xsl:when>
                  <xsl:otherwise>_unknown_</xsl:otherwise>
                </xsl:choose>
              </xsl:variable>
              <Group>
                <Id>
                  <xsl:value-of select="$_id" />
                </Id>
              </Group>
              <xsl:call-template name="fileModes">
                <xsl:with-param name="mode" select="substring($oMode,2,1)" />
              </xsl:call-template>
            </Permission>
            <Permission>
              <User>
                <Type>NPE</Type>
                <Id>Other</Id>
              </User>
              <xsl:call-template name="fileModes">
                <xsl:with-param name="mode" select="substring($oMode,3,1)" />
              </xsl:call-template>
            </Permission>
          </Permissions>
          <xsl:call-template name="genPath">
            <xsl:with-param name="_fn" select="./data/path/item/name/@i" />
          </xsl:call-template>
        </xsl:element>
      </After>
      <xsl:call-template name="emitOutcome" />
      <xsl:call-template name="processIncidentals" />

      <!-- 20221221: We want path details for this filesystem related activity -->
      <xsl:call-template name="processPathIncidentals" />
    </Update>
  </xsl:template>

  <!-- emitChdir -->
  <xsl:template name="emitChdir">
    <Update>
      <xsl:variable name="_obj" select="./data/path/item/name/@i" />

      <!-- 20221222: The mode attribute can have multiple strings before the mode as per file,suid,755 so get the last value in a csv list -->
      <xsl:variable name="oMode" select="tokenize(./data/path/item/mode/@i, ',')[last()]" />

      <!--
      <xsl:variable name="oMode" select="substring-after(./data/path/item/mode/@i, ',')" />
      -->
      <xsl:variable name="_objT">

        <!-- We are either a directory (aka Folder) or a File -->
        <xsl:choose>
          <xsl:when test="matches(./data/path/item/mode/@i,'^dir')">Folder</xsl:when>
          <xsl:otherwise>File</xsl:otherwise>
        </xsl:choose>
      </xsl:variable>
      <Before>
        <xsl:element name="{$_objT}">
          <Path>
            <xsl:value-of select="data/cwd/cwd/@i" />
          </Path>
        </xsl:element>
      </Before>
      <After>
        <xsl:element name="{$_objT}">
          <Permissions>
            <Permission>

              <!-- In the case where we can't find the user or group (e.g. no such file or directory), we use an '_unknown_' user or group -->
              <xsl:variable name="_id">
                <xsl:choose>
                  <xsl:when test="./data/path/item/ouid/@i">
                    <xsl:value-of select="./data/path/item/ouid/@i" />
                  </xsl:when>
                  <xsl:otherwise>_unknown_</xsl:otherwise>
                </xsl:choose>
              </xsl:variable>
              <User>
                <xsl:call-template name="emitUserId">
                  <xsl:with-param name="_u" select="$_id" />
                </xsl:call-template>
              </User>
              <xsl:call-template name="fileModes">
                <xsl:with-param name="mode" select="substring($oMode,1,1)" />
              </xsl:call-template>
            </Permission>
            <Permission>

              <!-- In the case where we can't find the user or group (e.g. no such file or directory), we use an '_unknown_' user or group -->
              <xsl:variable name="_id">
                <xsl:choose>
                  <xsl:when test="./data/path/item/ogid/@i">
                    <xsl:value-of select="./data/path/item/ogid/@i" />
                  </xsl:when>
                  <xsl:otherwise>_unknown_</xsl:otherwise>
                </xsl:choose>
              </xsl:variable>
              <Group>
                <Id>
                  <xsl:value-of select="$_id" />
                </Id>
              </Group>
              <xsl:call-template name="fileModes">
                <xsl:with-param name="mode" select="substring($oMode,2,1)" />
              </xsl:call-template>
            </Permission>
            <Permission>
              <User>
                <Type>NPE</Type>
                <Id>Other</Id>
              </User>
              <xsl:call-template name="fileModes">
                <xsl:with-param name="mode" select="substring($oMode,3,1)" />
              </xsl:call-template>
            </Permission>
          </Permissions>
          <xsl:call-template name="genPath">
            <xsl:with-param name="_fn" select="./data/path/item/name/@i" />
          </xsl:call-template>
        </xsl:element>
      </After>
      <xsl:call-template name="emitOutcome" />
      <xsl:call-template name="processIncidentals" />

      <!-- 20221221: We want path details for this filesystem related activity -->
      <xsl:call-template name="processPathIncidentals" />
    </Update>
  </xsl:template>

  <!-- emitIDAM -->
  <xsl:template name="emitIDAM">
    <xsl:param name="act" />
    <xsl:param name="subact" />
    <xsl:choose>
      <xsl:when test="$act='del_user'">
        <Delete>
          <User>
            <xsl:variable name="deletedUser">
              <xsl:value-of select="./data/del_user/id/@i" />
              <xsl:value-of select="./data/del_user/acct/@i" />
            </xsl:variable>
            <xsl:call-template name="emitUserId">
              <xsl:with-param name="_u" select="$deletedUser" />
            </xsl:call-template>
          </User>
          <xsl:call-template name="emitOutcome" />
          <xsl:call-template name="processIncidentals" />
        </Delete>
      </xsl:when>
      <xsl:when test="$act='add_user'">
        <Create>
          <User>
            <xsl:variable name="addedUser">
              <xsl:value-of select="./data/add_user/id/@i" />
            </xsl:variable>
            <xsl:call-template name="emitUserId">
              <xsl:with-param name="_u" select="$addedUser" />
            </xsl:call-template>
          </User>
          <xsl:call-template name="emitOutcome" />
          <xsl:call-template name="processIncidentals" />
        </Create>
      </xsl:when>
      <xsl:when test="$act='add_group'">
        <Create>
          <Group>

            <!-- 20240510: As the group id can sometimes be of the form gname(gid), run it through the emitUserId template -->
            <xsl:variable name="_gid">
              <xsl:value-of select="./data/add_group/id/@i" />
              <xsl:if test="not(./data/add_group/id)">
                <xsl:value-of select="./data/add_group/acct/@i" />
              </xsl:if>
            </xsl:variable>
            <xsl:call-template name="emitUserId">
              <xsl:with-param name="_u" select="lower-case($_gid)" />
            </xsl:call-template>
          </Group>
          <xsl:call-template name="emitOutcome" />
          <xsl:call-template name="processIncidentals" />
        </Create>
      </xsl:when>
      <xsl:when test="$subact='add-shadow-group'">
        <Create>
          <Group>
            <Type>ShadowGroup</Type>
            <Id>
              <xsl:value-of select="./data/grp_mgmt/id/@i" />
            </Id>
          </Group>
          <xsl:call-template name="emitOutcome" />
          <xsl:call-template name="processIncidentals" />
        </Create>
      </xsl:when>
      <xsl:when test="matches($subact, 'modify-group|changing-group-passwd')">
        <Update>
          <After>
            <Group>
              <Id>
                <xsl:value-of select="./data/grp_mgmt/acct/@i" />
              </Id>
            </Group>
          </After>
          <xsl:call-template name="emitOutcome" />
          <xsl:call-template name="processIncidentals" />
        </Update>
      </xsl:when>
      <xsl:when test="./data/del_group or matches($subact, 'delete-group|delete-shadow-group')">
        <Delete>
          <Group>

            <!-- 20240510: As the group id can sometimes be of the form gname(gid), run it through the emitUserId template -->
            <xsl:variable name="_gid">
              <xsl:value-of select="./data/del_group/grp/@i" />
              <xsl:if test="not(./data/del_group/grp)">
                <xsl:value-of select="./data/del_group/id/@i" />
              </xsl:if>
              <xsl:value-of select="./data/grp_mgmt/acct/@i" />
              <xsl:value-of select="./data/grp_mgmt/id/@i" />
            </xsl:variable>
            <xsl:if test="$subact = 'delete-shadow-group'">
              <Type>ShadowGroup</Type>
            </xsl:if>
            <xsl:call-template name="emitUserId">
              <xsl:with-param name="_u" select="lower-case($_gid)" />
            </xsl:call-template>

            <!-- 20240511: Include the original provided id string if of the form gname(gid) -->
            <xsl:if test="contains($_gid, '(')">
              <Data Name="OriginalId" Value="{$_gid}" />
            </xsl:if>
          </Group>
          <xsl:call-template name="emitOutcome" />
          <xsl:call-template name="processIncidentals" />
        </Delete>
      </xsl:when>

      <!-- 20240510: grp_mgmt
      changing <file>; group <oldgname>/<gid>, new name: <newgroupname>
      changing <file>; group <oldgname>, new name: <newgroupname>
      changing <file>; group <oldgname>/<gid>, new gid: <newgid>
      changing <file>; group <oldgname>/<gid>, new password
      
      -->
      <xsl:when test="$act='grp_mgmt' and starts-with($subact, 'changing ')">
        <xsl:variable name="op" select="data/grp_mgmt/op/@i" />
        <Update>
          <xsl:analyze-string select="$op" regex="^changing ([^;]+); group ([^/]+)/(\d+), new (name|gid): (.+)$">
            <xsl:matching-substring>
              <Before>
                <Group>
                  <Id>
                    <xsl:value-of select="regex-group(2)" />
                  </Id>
                  <Data Name="Gid" Value="{regex-group(3)}" />
                  <Data Name="File" Value="{regex-group(1)}" />
                </Group>
              </Before>
              <After>
                <Group>
                  <xsl:choose>
                    <xsl:when test="regex-group(4) = 'name'">
                      <Id>
                        <xsl:value-of select="regex-group(5)" />
                      </Id>
                      <Data Name="Gid" Value="{regex-group(3)}" />
                      <Data Name="File" Value="{regex-group(1)}" />
                    </xsl:when>
                    <xsl:otherwise>
                      <Id>
                        <xsl:value-of select="regex-group(2)" />
                      </Id>
                      <Data Name="Gid" Value="{regex-group(5)}" />
                      <Data Name="File" Value="{regex-group(1)}" />
                    </xsl:otherwise>
                  </xsl:choose>
                </Group>
              </After>
            </xsl:matching-substring>
            <xsl:non-matching-substring>
              <xsl:analyze-string select="$op" regex="^changing ([^;]+); group ([^/]+), new name: (.+)$">
                <xsl:matching-substring>
                  <Before>
                    <Group>
                      <Type>ShadowGroup</Type>
                      <Id>
                        <xsl:value-of select="regex-group(2)" />
                      </Id>
                      <Data Name="File" Value="{regex-group(1)}" />
                    </Group>
                  </Before>
                  <After>
                    <Group>
                      <Type>ShadowGroup</Type>
                      <Id>
                        <xsl:value-of select="regex-group(3)" />
                      </Id>
                      <Data Name="File" Value="{regex-group(1)}" />
                    </Group>
                  </After>
                </xsl:matching-substring>
                <xsl:non-matching-substring>
                  <xsl:analyze-string select="$op" regex="^changing ([^;]+); group ([^/]+)/(\d+), new password$">
                    <xsl:matching-substring>
                      <Before>
                        <Group>
                          <Id>
                            <xsl:value-of select="regex-group(2)" />
                          </Id>
                          <Data Name="Gid" Value="{regex-group(3)}" />
                          <Data Name="File" Value="{regex-group(1)}" />
                        </Group>
                      </Before>
                      <After>
                        <Group>
                          <Id>
                            <xsl:value-of select="regex-group(2)" />
                          </Id>
                          <Data Name="Gid" Value="{regex-group(3)}" />
                          <Data Name="File" Value="{regex-group(1)}" />
                          <Data Name="Update" Value="GroupPassword" />
                        </Group>
                      </After>
                    </xsl:matching-substring>
                  </xsl:analyze-string>
                </xsl:non-matching-substring>
              </xsl:analyze-string>
            </xsl:non-matching-substring>
          </xsl:analyze-string>
          <xsl:call-template name="emitOutcome" />
          <xsl:call-template name="processIncidentals" />
        </Update>
      </xsl:when>

      <!-- 20211017 - treat unlock password as Account unlock -->
      <xsl:when test="matches($subact, 'faillock-reset|unlocked-password')">
        <Authenticate>
          <Action>AccountUnlock</Action>
          <User>
            <xsl:call-template name="emitUserId">
              <xsl:with-param name="_u" select="./data//id/@i" />
            </xsl:call-template>
          </User>
          <xsl:call-template name="emitOutcome" />
          <xsl:call-template name="processIncidentals" />
        </Authenticate>
      </xsl:when>

      <!-- 20211222 - timed lock/unlock of accounts -->
      <xsl:when test="$act = 'resp_acct_unlock_timed'">
        <Authenticate>
          <Action>AccountUnlock</Action>
          <User>
            <xsl:call-template name="emitUserId">
              <xsl:with-param name="_u" select="./data//uid[last()]/@i" />
            </xsl:call-template>
          </User>
          <xsl:call-template name="emitOutcome" />
          <xsl:call-template name="processIncidentals" />
        </Authenticate>
      </xsl:when>
      <xsl:when test="matches($act, 'resp_acct_lock_timed|resp_acct_lock')">
        <Authenticate>
          <Action>AccountLock</Action>
          <User>
            <xsl:call-template name="emitUserId">
              <xsl:with-param name="_u" select="./data//uid[last()]/@i" />
            </xsl:call-template>
          </User>
          <xsl:call-template name="emitOutcome" />
          <xsl:call-template name="processIncidentals" />
        </Authenticate>
      </xsl:when>
      <xsl:when test="$act = 'acct_lock'">
        <Authenticate>
          <Action>AccountLock</Action>
          <User>
            <xsl:call-template name="emitUserId">
              <xsl:with-param name="_u" select="./data//id/@i" />
            </xsl:call-template>
          </User>
          <xsl:call-template name="emitOutcome" />
          <xsl:call-template name="processIncidentals" />
        </Authenticate>
      </xsl:when>
      <xsl:when test="matches($subact, 'deleting-user-from-group|deleting-user-from-shadow-group')">
        <Authorise>
          <User>
            <xsl:call-template name="emitUserId">
              <xsl:with-param name="_u" select="./data/user_mgmt/id/@i" />
            </xsl:call-template>
          </User>
          <RemoveGroups>
            <Group>
              <Id>
                <xsl:value-of select="./data/user_mgmt/grp/@i" />
              </Id>
            </Group>
          </RemoveGroups>
          <xsl:call-template name="emitOutcome" />
          <xsl:call-template name="processIncidentals" />
        </Authorise>
      </xsl:when>
      <xsl:when test="matches($subact,'delete-user-from-group|delete-user-from-shadow-group')">
        <Authorise>
          <User>
            <xsl:call-template name="emitUserId">
              <xsl:with-param name="_u" select="./data/user_mgmt/acct/@i" />
            </xsl:call-template>
          </User>
          <RemoveGroups>
            <Group>
              <Id>
                <xsl:value-of select="./data/user_mgmt/grp/@i" />
              </Id>
            </Group>
          </RemoveGroups>
          <xsl:call-template name="emitOutcome" />
          <xsl:call-template name="processIncidentals" />
        </Authorise>
      </xsl:when>
      <xsl:when test="matches($subact, 'add-user-to-group|update-member-in-group|add-to-shadow-group|add-user-to-shadow-group|update-member-in-shadow-group')">
        <Authorise>
          <User>
            <xsl:call-template name="emitUserId">
              <xsl:with-param name="_u" select="./data/user_mgmt/acct/@i" />
            </xsl:call-template>
          </User>
          <AddGroups>
            <Group>
              <Id>
                <xsl:value-of select="./data/user_mgmt/grp/@i" />
              </Id>
            </Group>
          </AddGroups>
          <xsl:call-template name="emitOutcome" />
          <xsl:call-template name="processIncidentals" />
        </Authorise>
      </xsl:when>
      <xsl:when test="$subact='changing-group'">
        <Authorise>
          <User>
            <xsl:call-template name="emitUserId">
              <xsl:with-param name="_u" select="./data/grp_mgmt/auid/@i" />
            </xsl:call-template>
          </User>
          <AddGroups>
            <Group>
              <Id>
                <xsl:value-of select="./data/grp_mgmt/grp/@i" />
              </Id>
            </Group>
          </AddGroups>
          <xsl:call-template name="emitOutcome" />
          <xsl:call-template name="processIncidentals" />
        </Authorise>
      </xsl:when>
      <xsl:when test="$act='chgrp_id' and $subact='changing'">
        <Authorise>
          <User>
            <xsl:call-template name="emitUserId">
              <xsl:with-param name="_u" select="./data/chgrp_id/auid/@i" />
            </xsl:call-template>
          </User>
          <AddGroups>
            <Group>
              <Id>
                <xsl:value-of select="./data/chgrp_id/new_group/@i" />
              </Id>
            </Group>
          </AddGroups>
          <xsl:call-template name="emitOutcome" />
          <xsl:call-template name="processIncidentals" />
        </Authorise>
      </xsl:when>

      <!-- 20211017 -->
      <xsl:when test="data/user_mgmt and matches($subact, '^changed-password-aging')">
        <Update>
          <After>
            <Configuration>
              <Data Name="Inactivity" Value="{./data/user_mgmt/inact/@i}" />
              <Data Name="Warning" Value="{./data/user_mgmt/warn/@i}" />
              <Data Name="Minimum" Value="{./data/user_mgmt/min/@i}" />
              <Data Name="Maximum" Value="{./data/user_mgmt/max/@i}" />
            </Configuration>
            <User>
              <xsl:call-template name="emitUserId">
                <xsl:with-param name="_u">
                  <xsl:choose>
                    <xsl:when test="./data/user_mgmt/id/@i">
                      <xsl:value-of select="./data/user_mgmt/id/@i" />
                    </xsl:when>
                    <xsl:otherwise>_NoUserId_in_user_mgmt</xsl:otherwise>
                  </xsl:choose>
                </xsl:with-param>
              </xsl:call-template>
            </User>
          </After>
          <xsl:call-template name="emitOutcome" />
          <xsl:call-template name="processIncidentals" />
        </Update>
      </xsl:when>

      <!-- Misc acct actions (but no information avaiable aside from user id) -->

      <!-- 20211017 - add expired-password, 20211221 - add modify-account -->
      <xsl:when test="data/user_mgmt and matches($subact, '^add-|^changing-|^change-|moving-home-dir|^updating-|^update-|^modify-|^deleting-|^delete-|^expired-password')">
        <Update>
          <After>
            <User>
              <xsl:call-template name="emitUserId">
                <xsl:with-param name="_u">
                  <xsl:choose>
                    <xsl:when test="./data/user_mgmt/id/@i">
                      <xsl:value-of select="./data/user_mgmt/id/@i" />
                    </xsl:when>
                    <xsl:when test="./data/user_mgmt/acct/@i">
                      <xsl:value-of select="./data/user_mgmt/acct/@i" />
                    </xsl:when>
                    <xsl:otherwise>_NoUserId_in_user_mgmt</xsl:otherwise>
                  </xsl:choose>
                </xsl:with-param>
              </xsl:call-template>
            </User>
          </After>
          <xsl:call-template name="emitOutcome" />
          <xsl:call-template name="processIncidentals" />
        </Update>
      </xsl:when>
    </xsl:choose>
  </xsl:template>

  <!-- 20211017: SELinux Role Changes -->
  <xsl:template name="emitSelinuxRoles">
    <xsl:choose>
      <xsl:when test="data/role_assign">

        <!-- Primary info in role_assign/acct i="burn old-seuser=? old-role=? old-range=? new-seuser=unconfined_u new-role=system_r,unconfined_r new-range=s0-s0:c0.c1023" -->
        <Authorise>
          <User>
            <xsl:call-template name="emitUserId">
              <xsl:with-param name="_u" select="substring-before(./data/role_assign/acct/@i, ' ')" />
            </xsl:call-template>
          </User>
          <xsl:variable name="roles" select="substring-after(./data/role_assign/acct/@i, ' ')" />
          <AddGroups>
            <xsl:for-each select="tokenize($roles, ' ')">
              <xsl:analyze-string select="." regex="^([^=]+)=(.+)">
                <xsl:matching-substring>
                  <xsl:if test="starts-with(regex-group(1), 'new')">
                    <Group>
                      <Type>
                        <xsl:value-of select="substring-after(regex-group(1), 'new-')" />
                      </Type>
                      <Id>
                        <xsl:value-of select="regex-group(2)" />
                      </Id>
                    </Group>
                  </xsl:if>
                </xsl:matching-substring>
              </xsl:analyze-string>
            </xsl:for-each>
          </AddGroups>
          <RemoveGroups>
            <xsl:for-each select="tokenize($roles, ' ')">
              <xsl:analyze-string select="." regex="^([^=]+)=(.+)">
                <xsl:matching-substring>
                  <xsl:if test="starts-with(regex-group(1), 'old')">
                    <Group>
                      <Type>
                        <xsl:value-of select="substring-after(regex-group(1), 'old-')" />
                      </Type>
                      <Id>
                        <xsl:value-of select="regex-group(2)" />
                      </Id>
                    </Group>
                  </xsl:if>
                </xsl:matching-substring>
              </xsl:analyze-string>
            </xsl:for-each>
          </RemoveGroups>
          <xsl:call-template name="emitOutcome" />
          <xsl:call-template name="processIncidentals" />
        </Authorise>
      </xsl:when>
    </xsl:choose>
  </xsl:template>

  <!-- 20230614: -->
  <xsl:template name="emitSelinuxUpdate">
    <Update>
      <After>
        <Object>
          <Description>Selinux enforcing mode</Description>
          <Data Name="Setenforce" Value="{data/user_mac_status/enforcing/@i}" />
        </Object>
      </After>
      <xsl:call-template name="emitOutcome" />
      <xsl:call-template name="processIncidentals" />
      <xsl:call-template name="processPathIncidentals" />
    </Update>
  </xsl:template>

  <!-- -->
  <xsl:template name="emitNameSpace">
    <xsl:param name="_sact" />
    <xsl:choose>
      <xsl:when test="$_sact = 'setns'">
        <Update>
          <After>
            <Object>
              <Type>Namespace</Type>
              <Id>
                <xsl:value-of select="data/syscall/a0/@i" />
              </Id>
              <Name>
                <xsl:value-of select="data/syscall/a1/@i" />
              </Name>
              <Description>Join namespace</Description>
            </Object>
          </After>
          <xsl:call-template name="emitOutcome" />
          <xsl:call-template name="processIncidentals" />
          <xsl:call-template name="processPathIncidentals" />
        </Update>
      </xsl:when>
      <xsl:when test="$_sact = 'unshare'">
        <Update>
          <After>
            <Object>
              <Type>Context</Type>
              <Name>
                <xsl:choose>
                  <xsl:when test="data/syscall/a0/@i = '0x0'">None</xsl:when>
                  <xsl:otherwise>
                    <xsl:value-of select="data/syscall/a0/@i" />
                  </xsl:otherwise>
                </xsl:choose>
              </Name>
              <Description>Disassociate execution context</Description>
            </Object>
          </After>
          <xsl:call-template name="emitOutcome" />
          <xsl:call-template name="processIncidentals" />
          <xsl:call-template name="processPathIncidentals" />
        </Update>
      </xsl:when>
      <xsl:otherwise>
        <Unknown>
          <xsl:call-template name="processIncidentals" />
          <xsl:call-template name="processPathIncidentals" />
        </Unknown>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

  <!-- Virtualisation -->
  <xsl:template name="emitVirtualControl">
    <xsl:choose>
      <xsl:when test="data/virt_control/op/@i = 'start'">
        <Create>
          <Object>
            <Type>
              <xsl:value-of select="concat('VirtualMachine-', data/virt_control/virt/@i)" />
            </Type>
            <Id>
              <xsl:value-of select="data/virt_control/uuid/@i|data/virt_control/ctr_id_short/@i" />
            </Id>
            <Name>
              <xsl:value-of select="data/virt_control/vm/@i" />
            </Name>
          </Object>
          <xsl:call-template name="emitOutcome" />
          <xsl:call-template name="processIncidentals" />
        </Create>
      </xsl:when>
      <xsl:when test="data/virt_control/op/@i = 'stop'">
        <Delete>
          <Object>
            <Type>
              <xsl:value-of select="concat('VirtualMachine-', data/virt_control/virt/@i)" />
            </Type>
            <Id>
              <xsl:value-of select="data/virt_control/uuid/@i" />
            </Id>
            <Name>
              <xsl:value-of select="data/virt_control/vm/@i" />
            </Name>
          </Object>
          <xsl:call-template name="emitOutcome" />

          <!-- Create data elements for all keys not already catered for -->
          <xsl:for-each select="data/virt_control/*[not(self::subj|self::ses|self::uuid|self::auid|self::uid|self::pid|self::res|self::terminal|self::addr|self::exe|self::op|self::hostname||self::reason)]">
            <Data Name="{name(.)}" Value="{@i}" />
          </xsl:for-each>
          <xsl:if test="count(data/virt_control/hostname) > 1">
            <Data Name="vm-hostname" Value="{data/virt_control/hostname[2]/@i}" />
          </xsl:if>
          <xsl:call-template name="processIncidentals" />
        </Delete>
      </xsl:when>
      <xsl:when test="data/virt_control/op/@i = 'resize'">
        <Update>
          <After>
            <Object>
              <Type>
                <xsl:value-of select="concat('VirtualMachine-', data/virt_control/virt/@i)" />
              </Type>
              <xsl:if test="data/virt_control/uuid">
                <Id>
                  <xsl:value-of select="data/virt_control/uuid/@i" />
                </Id>
              </xsl:if>
              <Name>
                <xsl:value-of select="data/virt_control/vm/@i" />
              </Name>
            </Object>
          </After>
          <xsl:call-template name="emitOutcome" />
          <xsl:call-template name="processIncidentals" />
        </Update>
      </xsl:when>
      <xsl:otherwise>
        <Process>
          <Action>Execute</Action>
          <Type>Service</Type>
          <Command>
            <xsl:value-of select="data/virt_control/exe/@i" />
          </Command>
          <xsl:call-template name="emitOutcome" />
          <xsl:call-template name="processIncidentals" />
        </Process>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>
  <xsl:template name="emitVirtualResource">
    <Create>
      <Association>
        <Objects>
          <Object>
            <Type>
              <xsl:value-of select="concat('VirtualMachine-', data/virt_resource/virt/@i)" />
            </Type>
            <Id>
              <xsl:value-of select="data/virt_resource/uuid/@i" />
            </Id>
            <Name>
              <xsl:value-of select="data/virt_resource/vm/@i" />
            </Name>
          </Object>
          <Object>
            <Type>
              <xsl:value-of select="data/virt_resource/resrc/@i" />
            </Type>
            <xsl:if test="data/virt_resource/cgroup">
              <Name>
                <xsl:value-of select="data/virt_resource/cgroup/@i" />
              </Name>
            </xsl:if>
            <xsl:if test="data/virt_resource/new-disk">
              <Name>
                <xsl:value-of select="data/virt_resource/new-disk/@i" />
              </Name>
            </xsl:if>
            <xsl:if test="data/virt_resource/net">
              <Name>
                <xsl:value-of select="data/virt_resource/net/@i" />
              </Name>
            </xsl:if>
            <xsl:if test="data/virt_resource/new-net">
              <Name>
                <xsl:value-of select="data/virt_resource/new-net/@i" />
              </Name>
            </xsl:if>
            <xsl:if test="data/virt_resource/new-chardev">
              <Name>
                <xsl:value-of select="data/virt_resource/new-chardev/@i" />
              </Name>
            </xsl:if>
            <xsl:if test="data/virt_resource/old-mem">
              <Data Name="old-mem" Value="{data/virt_resource/old-mem/@i}" />
            </xsl:if>
            <xsl:if test="data/virt_resource/new-mem">
              <Data Name="new-mem" Value="{data/virt_resource/new-mem/@i}" />
            </xsl:if>
            <xsl:if test="data/virt_resource/old-vcpu">
              <Data Name="old-vcpu" Value="{data/virt_resource/old-vcpu/@i}" />
            </xsl:if>
            <xsl:if test="data/virt_resource/new-vcpu">
              <Data Name="new-vcpu" Value="{data/virt_resource/new-vcpu/@i}" />
            </xsl:if>
            <xsl:if test="data/virt_resource/old-disk">
              <Data Name="old-disk" Value="{data/virt_resource/old-disk/@i}" />
            </xsl:if>
            <xsl:if test="data/virt_resource/old-net">
              <Data Name="old-net" Value="{data/virt_resource/old-net/@i}" />
            </xsl:if>
            <xsl:if test="data/virt_resource/old-chardev">
              <Data Name="old-chardev" Value="{data/virt_resource/old-chardev/@i}" />
            </xsl:if>
            <xsl:if test="data/virt_resource/class">
              <Data Name="class" Value="{data/virt_resource/class/@i}" />
            </xsl:if>
            <xsl:if test="data/virt_resource/acl">
              <Data Name="acl" Value="{data/virt_resource/acl/@i}" />
            </xsl:if>
            <xsl:if test="data/virt_resource/category">
              <Data Name="category" Value="{data/virt_resource/category/@i}" />
            </xsl:if>
            <xsl:if test="data/virt_resource/path">
              <Data Name="path" Value="{data/virt_resource/path/@i}" />
            </xsl:if>
          </Object>
        </Objects>
        <xsl:call-template name="processIncidentals" />
      </Association>
      <xsl:call-template name="emitOutcome" />
    </Create>
  </xsl:template>

  <!-- Container operations -->
  <xsl:template name="emitContainerOp">
    <Description>Set the audit container id for a process</Description>
    <Create>
      <Association>
        <Objects>
          <Object>
            <Type>Process</Type>
            <Id>
              <xsl:value-of select="data//opid/@i" />
            </Id>
          </Object>
          <Object>
            <Type>ContainerId</Type>
            <Id>
              <xsl:value-of select="data//contid/@i" />
            </Id>
            <Data Name="OldContainerId">
              <xsl:attribute name="Value">
                <xsl:choose>
                  <xsl:when test="data//oldcontid/@i = '18446744073709551615'">unset</xsl:when>
                  <xsl:otherwise>
                    <xsl:value-of select="data//oldcontid/@i" />
                  </xsl:otherwise>
                </xsl:choose>
              </xsl:attribute>
            </Data>
          </Object>
        </Objects>
        <xsl:call-template name="processIncidentals" />
      </Association>
      <xsl:call-template name="emitOutcome" />
    </Create>
  </xsl:template>

  <!-- 20211107:
  Alert - Audit -->
  <xsl:template name="emitAlert">
    <xsl:param name="_sact" />
    <Alert>
      <xsl:choose>
        <xsl:when test="$_sact = 'event_listener'">
          <Type>Change</Type>
          <Description>Access to audit netlink multicast socket</Description>
          <Data Name="ConnectionType" Value="{data//op/@i}" />
          <Data Name="ConnectionResult" Value="{data//res/@i}" />
          <Data Name="NetlinkGroup" Value="{data//nlmcgrp/@i|data//nl-mcgrp/@i}" />
        </xsl:when>
      </xsl:choose>
      <xsl:call-template name="processIncidentals" />
    </Alert>
  </xsl:template>

  <!-- Audit configuration changes
  20221219 - Rework to split config/feature/daemon
  -->
  <xsl:template name="auditConfigChange_config">
    <Update>

      <!-- Format
      op=set <config_item>=<value> old=<value> ...
      op={add|remove}_rule audit_enabled=<value> res=0
      context_items op={add|remove}_rule key=<key> list=<filter_type> res=<result>
      op=trim res=1
      op=make_equiv old=<oldvalue> new=<newvalue> res=<result>
      op=tty_set old-enabled=<oldvalue0> new-enabled=<newvalue0> old-log_passwd=<oldvalue1> new-log_passwd=<newvalue1> res=<result>
      op=autoremove_rule path=<path> key=<key> list=<filter_type> res=1
      op=remove_rule dir=<path> key=<key> list=<filter_type> res=1
      op=seccomp-logging actions=<actions> old-actions=<old_actions> res=<result>
      -->
      <xsl:variable name="_op">
        <xsl:value-of select="data/config_change/op/@i" />
      </xsl:variable>
      <xsl:variable name="_item_name">
        <xsl:choose>
          <xsl:when test="$_op='set'">
            <xsl:value-of select="name(data/config_change/node()[position()=last()-1])" />
          </xsl:when>
          <xsl:when test="ends-with($_op, 'rule') and exists(data/config_change/audit_enabled)">audit_enabled</xsl:when>
          <xsl:when test="$_op='trim'">directoryWatches</xsl:when>
          <xsl:when test="$_op='make_equiv'">directoryWatches</xsl:when>
          <xsl:when test="$_op='tty_set'">ttyAudit</xsl:when>
          <xsl:when test="$_op='seccomp-logging'">secureComputing</xsl:when>
        </xsl:choose>
      </xsl:variable>
      <xsl:variable name="_item_after">
        <xsl:choose>
          <xsl:when test="$_op='set'">
            <xsl:value-of select="data/config_change/node()[position()=last()-1]/@i" />
          </xsl:when>
          <xsl:when test="ends-with($_op, 'rule') and exists(data/config_change/audit_enabled)">
            <xsl:value-of select="data/config_change/audit_enabled/@i" />
          </xsl:when>
          <xsl:when test="ends-with($_op, 'rule')"></xsl:when>
          <xsl:when test="$_op='make_equiv'">
            <xsl:value-of select="data/config_change/new/@i" />
          </xsl:when>
          <xsl:when test="$_op='tty_set'">
            <xsl:value-of select="concat('enabled=', data/config_change/new-enabled/@i, ', new-log_passwd=', data/config_change/new-log_passwd/@i)" />
          </xsl:when>
          <xsl:when test="$_op='seccomp-logging'">
            <xsl:value-of select="data/config_change/actions/@i" />
          </xsl:when>
        </xsl:choose>
      </xsl:variable>
      <xsl:variable name="_item_before">
        <xsl:choose>
          <xsl:when test="exists(data/config_change/old)">
            <xsl:value-of select="data/config_change/old/@i" />
          </xsl:when>
          <xsl:when test="$_op='tty_set'">
            <xsl:value-of select="concat('enabled=', data/config_change/old-enabled/@i, ', new-log_passwd=', data/config_change/old-log_passwd/@i)" />
          </xsl:when>
          <xsl:when test="$_op='seccomp-logging'">
            <xsl:value-of select="data/config_change/old-actions/@i" />
          </xsl:when>
        </xsl:choose>
      </xsl:variable>
      <xsl:variable name="_itemFilterKey">
        <xsl:if test="data/config_change/key">
          <xsl:value-of select="data/config_change/key/@i" />
        </xsl:if>
      </xsl:variable>
      <xsl:variable name="_item_additional">
        <xsl:if test="ends-with(data/config_change/op/@i, 'rule') and exists(data/config_change/list)">

          <!-- Record the list type -->
          <xsl:value-of select="concat('list:', data/config_change/list/@i)" />
          <xsl:if test="exists(data/config_change/path)">
            <xsl:value-of select="concat(' path:', data/config_change/path/@i)" />
          </xsl:if>
          <xsl:if test="exists(data/config_change/dir)">
            <xsl:value-of select="concat(' dir:', data/config_change/dir/@i)" />
          </xsl:if>
        </xsl:if>
      </xsl:variable>
      <xsl:if test="string-length($_item_before) > 0">
        <Before>
          <Configuration>
            <Type>
              <xsl:value-of select="$_op" />
            </Type>
            <xsl:if test="string-length($_item_name) >0">
              <Name>
                <xsl:value-of select="$_item_name" />
              </Name>
            </xsl:if>
            <Description>Linux Auditd configuration item</Description>
            <Data Name="old_value" Value="{$_item_before}" />
            <xsl:if test="string-length($_item_additional) > 0">
              <Data Name="RuleMedatata" Value="{$_item_additional}" />
            </xsl:if>
            <xsl:if test="string-length($_itemFilterKey) > 0">
              <Data Name="RuleFilterKey" Value="{$_itemFilterKey}" />
            </xsl:if>
          </Configuration>
        </Before>
      </xsl:if>
      <After>
        <Configuration>
          <Type>
            <xsl:value-of select="$_op" />
          </Type>
          <xsl:if test="string-length($_item_name) >0">
            <Name>
              <xsl:value-of select="$_item_name" />
            </Name>
          </xsl:if>
          <Description>Linux Auditd configuration item</Description>
          <xsl:if test="string-length($_item_after) > 0">
            <Data Name="new_value" Value="{$_item_after}" />
          </xsl:if>
          <xsl:if test="string-length($_item_additional) > 0">
            <Data Name="RuleMedatata" Value="{$_item_additional}" />
          </xsl:if>
          <xsl:if test="string-length($_itemFilterKey) > 0">
            <Data Name="RuleFilterKey" Value="{$_itemFilterKey}" />
          </xsl:if>
        </Configuration>
      </After>
      <xsl:call-template name="emitOutcome" />
      <xsl:call-template name="processIncidentals" />
    </Update>
  </xsl:template>

  <!-- -->
  <xsl:template name="auditConfigChange_feature">
    <Update>

      <!-- Format feature=%s old=%u new=%u old_lock=%u new_lock=%u res=%d -->
      <Before>
        <Configuration>
          <Type>AuditdFeature</Type>
          <Name>
            <xsl:value-of select="data/feature_change/feature/@i" />
          </Name>
          <Data Name="old_value" Value="{data/feature_change/old/@i}" />
          <Data Name="old_lock" Value="{data/feature_change/old_lock/@i}" />
        </Configuration>
      </Before>
      <After>
        <Configuration>
          <Type>AuditdFeature</Type>
          <Name>
            <xsl:value-of select="data/feature_change/feature/@i" />
          </Name>
          <Data Name="old_value" Value="{data/feature_change/new/@i}" />
          <Data Name="old_lock" Value="{data/feature_change/new_lock/@i}" />
        </Configuration>
      </After>
      <xsl:call-template name="emitOutcome" />
      <xsl:call-template name="processIncidentals" />
    </Update>
  </xsl:template>

  <!-- -->
  <xsl:template name="auditConfigChange_daemon">
    <Update>

      <!-- Format
      op=reconfigure state=<state> auid=<audi> pid=<pid> subj=<subject_context> res=<result>
      -->
      <After>
        <Configuration>
          <Type>DaemonConfiguration</Type>
          <Name>
            <xsl:value-of select="data/daemon_config/op/@i" />
          </Name>
          <xsl:if test="data/daemon_config/state">
            <State>
              <xsl:value-of select="data/daemon_config/state/@i" />
            </State>
          </xsl:if>
        </Configuration>
      </After>
      <xsl:call-template name="emitOutcome" />
      <xsl:call-template name="processIncidentals" />
    </Update>
  </xsl:template>

  <!-- Configuration -->
  <xsl:template name="emitConfigChange">
    <xsl:param name="_change" />
    <Update>
      <xsl:choose>
        <xsl:when test="data/time_adjntpval or data/unknown_1333_ or data/time_injoffset">

          <!--
          Such events will now generate records of type AUDIT_TIME_ADJNTPVAL (or UNKNOWN_1333_ due to bug in Centos8) containing the following fields:
          - op= which value was adjusted:
          offset corresponding to the time_offset variable
          freq corresponding to the time_freq variable
          status corresponding to the time_status variable
          adjust corresponding to the time_adjust variable
          tick corresponding to the tick_usec variable
          tai corresponding to the timekeeping's TAI offset
          - old= the old value
          - new= the new value
          -->
          <xsl:if test="data/time_adjntpval or data/unknown_1333_">
            <Before>
              <xsl:for-each select="data/time_adjntpval|data/unknown_1333_">
                <Configuration>
                  <Type>Time Parameter</Type>
                  <Name>
                    <xsl:value-of select="concat('time_',op/@i)" />
                  </Name>
                  <Data Name="Parameter" Value="{old/@i}" />
                </Configuration>
              </xsl:for-each>
            </Before>
          </xsl:if>
          <After>
            <xsl:for-each select="data/time_adjntpval|data/unknown_1333_">
              <Configuration>
                <Type>Time Parameter</Type>
                <Name>
                  <xsl:value-of select="concat('time_', op/@i)" />
                </Name>
                <Data Name="Parameter" Value="{new/@i}" />
              </Configuration>
            </xsl:for-each>
            <xsl:if test="data/time_injoffset">

              <!--
              Emit an audit record whenever the system clock is changed (i.e. shifted
              by a non-zero offset) by a syscall from userspace. The syscalls than can
              (at the time of writing) trigger such record are:
              - settimeofday(2), stime(2), clock_settime(2) - via do_settimeofday64()
              - adjtimex(2), clock_adjtime(2) - via do_adjtimex()
              
              The new records have type AUDIT_TIME_INJOFFSET and contain the following
              fields:
              - sec - the 'seconds' part of the offset
              - nsec - the 'nanoseconds' part of the offset
              
              Example record (time was shifted backwards by ~16.125 seconds):
              
              type=TIME_INJOFFSET msg=audit(1530616049.652:13): sec=-16 nsec=124887145
              -->
              <Configuration>
                <Type>Time Value</Type>
                <Name>Sec.Nsec</Name>
                <Data Name="Parameter" Value="{concat(data/time_injoffset/sec/@i, '.',data/time_injoffset/nsec/@i) }" />
              </Configuration>
            </xsl:if>
          </After>
        </xsl:when>

        <!-- 20211107: -->
        <xsl:when test="data/system_runlevel">
          <Before>
            <Configuration>
              <Type>
                <xsl:value-of select="$_change" />
              </Type>
              <Data Name="Level" Value="{data//oldlevel/@i|data//old-level/@i}" />
            </Configuration>
          </Before>
          <After>
            <Configuration>
              <Type>
                <xsl:value-of select="$_change" />
              </Type>
              <Data Name="Level" Value="{data//newlevel/@i|data//new-level/@i}" />
            </Configuration>
          </After>
        </xsl:when>
        <xsl:otherwise>
          <After>
            <Configuration>
              <Type>
                <xsl:value-of select="$_change" />
              </Type>
            </Configuration>
          </After>
        </xsl:otherwise>
      </xsl:choose>
      <xsl:call-template name="emitOutcome" />
      <xsl:call-template name="processIncidentals" />
    </Update>
  </xsl:template>

  <!-- emitUmask -->
  <xsl:template name="emitUmask">
    <Update>
      <Before>
        <Object>
          <Type>FileMask</Type>
          <Description>
            <xsl:value-of select="data/syscall/exit/@i" />
          </Description>
        </Object>
      </Before>
      <After>
        <Object>
          <Type>FileMask</Type>
          <Description>
            <xsl:value-of select="data/syscall/a0/@i" />
          </Description>
        </Object>
      </After>
      <xsl:call-template name="emitOutcome" />
      <xsl:call-template name="processIncidentals" />
    </Update>
  </xsl:template>

  <!-- emitSoftwareUpdate -->
  <xsl:template name="emitSoftwareUpdate">
    <Update>
      <After>
        <Object>
          <Type>
            <xsl:value-of select="data/software_update/sw_type/@i" />
          </Type>
          <Name>
            <xsl:value-of select="data/software_update/sw/@i" />
          </Name>
        </Object>
      </After>
      <xsl:call-template name="emitOutcome" />
      <xsl:call-template name="processIncidentals" />
    </Update>
  </xsl:template>

  <!-- 20211017: emitIMA -->
  <xsl:template name="emitIMA">
    <xsl:param name="act" />
    <xsl:param name="subact" />
    <xsl:choose>
      <xsl:when test="$act = 'integrity_policy_rule'">
        <Approval>
          <Action>Accept</Action>
          <Subject>
            <Object>
              <Name>
                <xsl:value-of select="data//func/@i" />
              </Name>
            </Object>
          </Subject>
          <xsl:call-template name="emitOutcome" />
        </Approval>
      </xsl:when>
      <xsl:when test="$act = 'integrity_data'">
        <Approval>
          <Action>RequestApproval</Action>
          <Subject>
            <Object>
              <Name>
                <xsl:value-of select="data//name/@i" />
              </Name>
            </Object>
          </Subject>
          <Reason>
            <xsl:value-of select="replace(data/integrity_data/cause/@i, '&quot;', '')" />
          </Reason>
          <xsl:call-template name="emitOutcome" />
          <xsl:for-each select="data/integrity_data/*">
            <Data>
              <xsl:attribute name="Name">
                <xsl:value-of select="concat('Integrity','_', name(.))" />
              </xsl:attribute>
              <xsl:attribute name="Value">
                <xsl:value-of select="replace(@i, '&quot;', '')" />
              </xsl:attribute>
            </Data>
          </xsl:for-each>
        </Approval>
      </xsl:when>
    </xsl:choose>
  </xsl:template>

  <!-- 20211114: emitIntegrityPcr -->
  <xsl:template name="emitIntegrityPcr">
    <Alert>
      <Type>Other</Type>
      <Subject>
        <xsl:value-of select="data/integrity_pcr/name/@i" />
      </Subject>
      <Description>
        <xsl:choose>
          <xsl:when test="contains(data/integrity_pcr/cause/@i, 'ToMToU')">Opening a file for write when already open for read</xsl:when>
          <xsl:when test="contains(data/integrity_pcr/cause/@i, 'open_writers')">Opening a file for read when already open for write</xsl:when>
        </xsl:choose>
      </Description>
      <xsl:call-template name="processIncidentals" />
    </Alert>
  </xsl:template>

  <!-- emitLabelUpdate -->
  <xsl:template name="emitLabelUpdate">
    <Update>
      <After>
        <Object>
          <Type>Printer</Type>
          <Id>
            <xsl:value-of select="data/label_level_change/uri/@i" />
          </Id>
          <Name>
            <xsl:value-of select="data/label_level_change/printer/@i" />
          </Name>
          <Data Name="Banners" Value="{data/label_level_change/banners/@i}" />
          <Data Name="Range" Value="{data/label_level_change/range/@i}" />
        </Object>
      </After>
      <xsl:call-template name="emitOutcome" />
      <xsl:call-template name="processIncidentals" />
    </Update>
  </xsl:template>

  <!-- emitBPFUpdate -->
  <xsl:template name="emitBPFUpdate">
    <Update>
      <After>
        <Object>
          <Type>ProgramId</Type>
          <Id>
            <xsl:value-of select="data//progid/@i" />
          </Id>
        </Object>
      </After>
    </Update>
  </xsl:template>

  <!-- emitArchThreadState (20210101) -->
  <xsl:template name="emitArchThreadState">
    <Update>
      <After>
        <Object>
          <Id>
            <xsl:value-of select="data/syscall/pid/@i" />
          </Id>
          <Description>Update or get process or thread state</Description>
          <Data Name="CodeArgument" Value="{data/syscall/a0/@i}" />
        </Object>
      </After>
      <xsl:call-template name="emitOutcome" />
      <xsl:call-template name="processIncidentals" />
    </Update>
  </xsl:template>

  <!-- emitFileStatus -->
  <xsl:template name="emitFileStatus">
    <View>
      <File>
        <Path>
          <xsl:value-of select="data/path/item/name/@i" />
        </Path>
      </File>
      <xsl:call-template name="emitOutcome" />
      <xsl:call-template name="processIncidentals" />
      <xsl:call-template name="processPathIncidentals" />
    </View>
  </xsl:template>

  <!-- Authenticate -->
  <xsl:template name="emitAuthenticate">
    <Authenticate>
      <Action>
        <xsl:choose>
          <xsl:when test="./data/user_chauthtok/op/@i = 'change password'">ChangePassword</xsl:when>
          <xsl:when test="./data/user_end">Logoff</xsl:when>
          <xsl:otherwise>Logon</xsl:otherwise>
        </xsl:choose>
      </Action>
      <User>
        <xsl:variable name="u">
          <xsl:choose>
            <xsl:when test="./data//acct">
              <xsl:value-of select="./data//acct/@i" />
            </xsl:when>
            <xsl:when test="./data/user_start|./data/user_login|./data/user_end|./data/user_chauthtok">
              <xsl:value-of select="./data//id/@i" />
            </xsl:when>
          </xsl:choose>
        </xsl:variable>
        <xsl:call-template name="emitUserId">
          <xsl:with-param name="_u" select="$u" />
        </xsl:call-template>
      </User>
      <xsl:call-template name="emitOutcome" />
      <xsl:call-template name="processIncidentals" />
    </Authenticate>
  </xsl:template>

  <!-- Group Password Change -->

  <!-- 20240511: Make use of acct= to record the group name whose password is being changed -->
  <xsl:template name="emitGrpPasswordChange">
    <Authenticate>
      <Action>ChangePassword</Action>
      <Group>
        <xsl:call-template name="emitUserId">
          <xsl:with-param name="_u" select="data/grp_chauthtok/acct/@i" />
        </xsl:call-template>
      </Group>
      <xsl:call-template name="emitOutcome" />
      <xsl:call-template name="processIncidentals" />
    </Authenticate>
  </xsl:template>

  <!-- Setuser id -->
  <xsl:template name="emitSetuid">
    <Authenticate>
      <Action>Logon</Action>
      <xsl:variable name="u">
        <xsl:value-of select="./data/syscall/a0/@i" />
      </xsl:variable>
      <xsl:choose>
        <xsl:when test="ends-with(./data/syscall/syscall/@i, 'uid')">
          <User>
            <xsl:call-template name="emitUserId">
              <xsl:with-param name="_u" select="$u" />
            </xsl:call-template>
          </User>
        </xsl:when>
        <xsl:otherwise>
          <Group>
            <xsl:call-template name="emitUserId">
              <xsl:with-param name="_u" select="$u" />
            </xsl:call-template>
          </Group>
        </xsl:otherwise>
      </xsl:choose>
      <xsl:call-template name="emitOutcome" />
      <xsl:call-template name="processIncidentals" />
    </Authenticate>
  </xsl:template>

  <!-- External connections - connect/accept -->

  <!-- 20251220: Redo all socket system calls -->
  <xsl:template name="emitExternalConnection">
    <xsl:param name="_sact" />
    <xsl:choose>
      <xsl:when test="matches($_sact, '^socket$') or starts-with($_sact, 'accept') or matches($_sact, 'socketcall\((socket|accept)\)')">
        <Create>
          <Object>
            <Type>Socket</Type>

            <!-- Reform the socket addr detail -->
            <xsl:if test="exists(data/sockaddr)">
              <Description>
                <xsl:for-each select="data/sockaddr/*">
                  <xsl:value-of select="name(.)" />
                  <xsl:text>=</xsl:text>
                  <xsl:value-of select="@i" />
                  <xsl:if test="position() != last()">
                    <xsl:text> </xsl:text>
                  </xsl:if>
                </xsl:for-each>
              </Description>
            </xsl:if>
            <xsl:if test="exists(data/socketcall)">
              <Data Name="SocketCall">
                <xsl:attribute name="Value">
                  <xsl:for-each select="data/socketcall/*">
                    <xsl:value-of select="name(.)" />
                    <xsl:text>=</xsl:text>
                    <xsl:value-of select="@i" />
                    <xsl:if test="position() != last()">
                      <xsl:text> </xsl:text>
                    </xsl:if>
                  </xsl:for-each>
                </xsl:attribute>
              </Data>
            </xsl:if>
          </Object>
          <xsl:call-template name="emitOutcome" />
          <xsl:call-template name="processIncidentals" />
          <xsl:call-template name="processPathIncidentals" />
        </Create>
      </xsl:when>
      <xsl:when test="matches($_sact, 'getsockname|getpeername|recv|recvfrom|getsockopt|recvmsg') or matches($_sact, 'socketcall\((getsock|getpeername|recv|recvfrom|getsockopt|recvmsg)\)')">
        <View>
          <Object>
            <Type>Socket</Type>
            <Id>
              <xsl:value-of select="data/syscall/exit/@i" />
            </Id>
            <xsl:if test="exists(data/sockaddr)">
              <Description>
                <xsl:for-each select="data/sockaddr/*">
                  <xsl:value-of select="name(.)" />
                  <xsl:text>=</xsl:text>
                  <xsl:value-of select="@i" />
                  <xsl:if test="position() != last()">
                    <xsl:text> </xsl:text>
                  </xsl:if>
                </xsl:for-each>
              </Description>
            </xsl:if>
            <xsl:if test="exists(data/socketcall)">
              <Data Name="SocketCall">
                <xsl:attribute name="Value">
                  <xsl:for-each select="data/socketcall/*">
                    <xsl:value-of select="name(.)" />
                    <xsl:text>=</xsl:text>
                    <xsl:value-of select="@i" />
                    <xsl:if test="position() != last()">
                      <xsl:text> </xsl:text>
                    </xsl:if>
                  </xsl:for-each>
                </xsl:attribute>
              </Data>
            </xsl:if>
          </Object>
          <xsl:call-template name="emitOutcome" />
          <xsl:call-template name="processIncidentals" />
          <xsl:call-template name="processPathIncidentals" />
        </View>
      </xsl:when>

      <!-- 20251219: Support socketcall(setsockopt) -->
      <xsl:when test="starts-with($_sact, 'setsockopt') or matches($_sact, 'connect|bind|listen|send') or matches($_sact, 'socketcall\((bind|connect|setsockopt|send|sendto|sendmsg)\)')">
        <Update>
          <After>
            <Object>
              <Type>Socket</Type>
              <Id>
                <xsl:value-of select="data/syscall/a0/@i" />
              </Id>
              <xsl:if test="exists(data/sockaddr)">
                <Description>
                  <xsl:for-each select="data/sockaddr/*">
                    <xsl:value-of select="name(.)" />
                    <xsl:text>=</xsl:text>
                    <xsl:value-of select="@i" />
                    <xsl:if test="position() != last()">
                      <xsl:text> </xsl:text>
                    </xsl:if>
                  </xsl:for-each>
                </Description>
              </xsl:if>
              <xsl:if test="exists(data/socketcall)">
                <Data Name="SocketCall">
                  <xsl:attribute name="Value">
                    <xsl:for-each select="data/socketcall/*">
                      <xsl:value-of select="name(.)" />
                      <xsl:text>=</xsl:text>
                      <xsl:value-of select="@i" />
                      <xsl:if test="position() != last()">
                        <xsl:text> </xsl:text>
                      </xsl:if>
                    </xsl:for-each>
                  </xsl:attribute>
                </Data>
              </xsl:if>
            </Object>
          </After>
          <xsl:call-template name="emitOutcome" />
          <xsl:call-template name="processIncidentals" />
          <xsl:call-template name="processPathIncidentals" />
        </Update>
      </xsl:when>
      <xsl:when test="starts-with($_sact, 'shutdown') or matches($_sact, 'socketcall\((shutdown)\)')">
        <Delete>
          <Object>
            <Type>Socket</Type>
            <Id>
              <xsl:value-of select="data/syscall/a0/@i" />
            </Id>
            <xsl:if test="exists(data/sockaddr)">
              <Description>
                <xsl:for-each select="data/sockaddr/*">
                  <xsl:value-of select="name(.)" />
                  <xsl:text>=</xsl:text>
                  <xsl:value-of select="@i" />
                  <xsl:if test="position() != last()">
                    <xsl:text> </xsl:text>
                  </xsl:if>
                </xsl:for-each>
              </Description>
            </xsl:if>
          </Object>
          <xsl:call-template name="emitOutcome" />
          <xsl:call-template name="processIncidentals" />
          <xsl:call-template name="processPathIncidentals" />
        </Delete>
      </xsl:when>
    </xsl:choose>
  </xsl:template>

  <!-- Netfilter configurations -->
  <xsl:template name="emitNetFilterCfg">
    <Description>Netfilter Chain modified</Description>
    <Update>
      <After>
        <xsl:for-each select="data/netfilter_cfg">
          <Object>
            <Type>
              <xsl:value-of select="family/@i" />
            </Type>
            <Name>
              <xsl:value-of select="table/@i" />
            </Name>
            <Data Name="NumEntries" Value="{entries/@i}" />

            <!-- Operation will be register or replace -->
            <xsl:if test="op">
              <Data Name="Operation" Value="{op/@i}" />
            </xsl:if>
            <xsl:if test="../syscall/syscall">
              <Data Name="SystemCall" Value="{../syscall/syscall/@i}" />
            </xsl:if>
          </Object>
        </xsl:for-each>
      </After>
      <xsl:call-template name="emitOutcome" />
      <xsl:call-template name="processIncidentals" />
    </Update>
  </xsl:template>
  <xsl:template name="emitNetFilterPkt">
    <Description>Packet traversed Netfilter Chain</Description>
    <Network>
      <Open>
        <Source>
          <Device>
            <IPAddress>
              <xsl:value-of select="data/netfilter_pkt/saddr/@i" />
            </IPAddress>

            <!-- 20251219: Added sport if present -->
            <xsl:if test="data/netfilter_pkt/sport">
              <Port>
                <xsl:value-of select="data/netfilter_pkt/sport/@i" />
              </Port>
            </xsl:if>
          </Device>
          <TransportProtocol>

            <!-- Strip ipv6- from ipv6-icmp ... we are only allowed tcp, udp, icmp, igmp, other (20210101) -->
            <xsl:value-of select="upper-case(replace(data/netfilter_pkt/proto/@i, 'ipv6-',''))" />
          </TransportProtocol>
          <xsl:if test="data/netfilter_pkt/mark">
            <Data Name="Mark" Value="{data/netfilter_pkt/mark/@i}" />
          </xsl:if>
          <Data Name="Recorded-Protocol" Value="{data/netfilter_pkt/proto/@i}" />
        </Source>
        <Destination>
          <Device>
            <IPAddress>
              <xsl:value-of select="data/netfilter_pkt/daddr/@i" />
            </IPAddress>

            <!-- 20251219: Added dport if present -->
            <xsl:if test="data/netfilter_pkt/dport">
              <Port>
                <xsl:value-of select="data/netfilter_pkt/dport/@i" />
              </Port>
            </xsl:if>
          </Device>
        </Destination>
      </Open>
    </Network>
  </xsl:template>

  <!-- 20230601 - XFRM IPSec management -->
  <xsl:template name="XFRM_object">

    <!-- Emit data elements for an XFRM Security Policy database item or Security Association data base item -->
    <xsl:if test="data/mac_ipsec_event/src">
      <Data Name="SrcIP" Value="{data/mac_ipsec_event/src/@i}" />
    </xsl:if>
    <xsl:if test="data/mac_ipsec_event/src_prefixlen">
      <Data Name="SrcPrefixLen" Value="{data/mac_ipsec_event/src_prefixlen/@i}" />
    </xsl:if>
    <xsl:if test="data/mac_ipsec_event/dst">
      <Data Name="DstIP" Value="{data/mac_ipsec_event/dst/@i}" />
    </xsl:if>
    <xsl:if test="data/mac_ipsec_event/dst_prefixlen">
      <Data Name="DstPrefixLen" Value="{data/mac_ipsec_event/dst_prefixlen/@i}" />
    </xsl:if>

    <!-- 
    At this point we create data elements for all keys from mac_ipsec_event not already consumed
    -->
    <xsl:for-each select="data/mac_ipsec_event/*[not(self::src|self::dst|self::src_prefixlen|self::dst_prefixlen|self::op|self::spi|self::res|self::subj|self::ses|self::auid)]">
      <Data Name="{name(.)}" Value="{@i}" />
    </xsl:for-each>
  </xsl:template>

  <!-- -->
  <xsl:template name="emitXFRM">
    <xsl:param name="_sact" />
    <xsl:choose>

      <!-- Policy Add/Delete -->
      <xsl:when test="$_sact = 'SPD-add'">
        <Create>
          <Object>
            <Type>IPSec Security Policy database entry</Type>
            <xsl:call-template name="XFRM_object" />
          </Object>
          <xsl:call-template name="emitOutcome" />
          <xsl:call-template name="processIncidentals" />
        </Create>
      </xsl:when>
      <xsl:when test="$_sact = 'SPD-delete'">
        <Delete>
          <Object>
            <Type>IPSec Security Policy database entry</Type>
            <xsl:call-template name="XFRM_object" />
          </Object>
          <xsl:call-template name="emitOutcome" />
          <xsl:call-template name="processIncidentals" />
        </Delete>
      </xsl:when>

      <!-- Security Association Add/Delete -->
      <xsl:when test="$_sact = 'SAD-add'">
        <Create>
          <Object>
            <Type>IPSec Security Association database entry</Type>
            <xsl:if test="data/mac_ipsec_event/spi">
              <Id>
                <xsl:value-of select="data/mac_ipsec_event/spi/@i" />
              </Id>
            </xsl:if>
            <xsl:call-template name="XFRM_object" />
          </Object>
          <xsl:call-template name="emitOutcome" />
          <xsl:call-template name="processIncidentals" />
        </Create>
      </xsl:when>
      <xsl:when test="$_sact = 'SAD-delete'">
        <Delete>
          <Object>
            <Type>IPSec Security Association database entry</Type>
            <xsl:if test="data/mac_ipsec_event/spi">
              <Id>
                <xsl:value-of select="data/mac_ipsec_event/spi/@i" />
              </Id>
            </xsl:if>
            <xsl:call-template name="XFRM_object" />
          </Object>
          <xsl:call-template name="emitOutcome" />
          <xsl:call-template name="processIncidentals" />
        </Delete>
      </xsl:when>
      <xsl:when test="$_sact = 'SA-notfound' or $_sact = 'SA-icv-failure'">
        <View>
          <Object>
            <Type>IPSec Security Association database entry</Type>
            <xsl:if test="data/mac_ipsec_event/spi">
              <Id>
                <xsl:value-of select="data/mac_ipsec_event/spi/@i" />
              </Id>
            </xsl:if>
            <xsl:call-template name="XFRM_object" />
          </Object>
          <Outcome>
            <Success>false</Success>
          </Outcome>
          <xsl:call-template name="processIncidentals" />
        </View>
      </xsl:when>
      <xsl:when test="$_sact = 'SA-replay-overflow' or $_sact = 'SA-replayed-pkt'">
        <Update>
          <After>
            <Object>
              <Type>IPSec Security Association database entry</Type>
              <xsl:if test="data/mac_ipsec_event/spi">
                <Id>
                  <xsl:value-of select="data/mac_ipsec_event/spi/@i" />
                </Id>
              </xsl:if>
              <xsl:call-template name="XFRM_object" />
            </Object>
          </After>
          <Outcome>
            <Success>false</Success>
          </Outcome>
          <xsl:call-template name="processIncidentals" />
        </Update>
      </xsl:when>
    </xsl:choose>
  </xsl:template>

  <!-- User Device
  TODO: 
  better interpet keys like target
  determine device type USBMassStorage or Other one assumes
  other events
  -->
  <xsl:template name="emitUserDevice">

    <!-- 20240922: Decode the hex encoded device rule value -->
    <xsl:param name="op" />
    <xsl:choose>
      <xsl:when test="$op = 'discovered-device'">
        <View>
          <Object>
            <Id>
              <xsl:value-of select="data/user_device/device/@i" />
            </Id>
            <Data Name="device_rule">
              <xsl:attribute name="Value">
                <xsl:call-template name="decode_audit_nv_string">
                  <xsl:with-param name="str" select="data/user_device/device_rule/@i" />
                </xsl:call-template>
              </xsl:attribute>
            </Data>
          </Object>
          <xsl:call-template name="emitOutcome" />
          <xsl:call-template name="processIncidentals" />
        </View>
      </xsl:when>
      <xsl:when test="$op = 'changed-authorization-state-for'">
        <Update>
          <After>
            <Object>
              <Id>
                <xsl:value-of select="data/user_device/device/@i" />
              </Id>
              <Data Name="target" Value="{replace(data/user_device/target/@i, '&quot;', '')}" />
              <Data Name="device_rule">
                <xsl:attribute name="Value">
                  <xsl:call-template name="decode_audit_nv_string">
                    <xsl:with-param name="str" select="data/user_device/device_rule/@i" />
                  </xsl:call-template>
                </xsl:attribute>
              </Data>
            </Object>
          </After>
          <xsl:call-template name="emitOutcome" />
          <xsl:call-template name="processIncidentals" />
        </Update>
      </xsl:when>
      <xsl:when test="$op = 'inserted-device'">
        <Install>
          <Hardware>
            <Type>USBMassStorage</Type>
            <Id>
              <xsl:value-of select="data/user_device/device/@i" />
            </Id>
            <Data Name="device_rule">
              <xsl:attribute name="Value">
                <xsl:call-template name="decode_audit_nv_string">
                  <xsl:with-param name="str" select="data/user_device/device_rule/@i" />
                </xsl:call-template>
              </xsl:attribute>
            </Data>
          </Hardware>
          <xsl:call-template name="emitOutcome" />
          <xsl:call-template name="processIncidentals" />
        </Install>
      </xsl:when>
      <xsl:when test="$op = 'removed-device'">
        <Uninstall>
          <Hardware>
            <Type>USBMassStorage</Type>
            <Id>
              <xsl:value-of select="data/user_device/device/@i" />
            </Id>
            <Data Name="device_rule">
              <xsl:attribute name="Value">
                <xsl:call-template name="decode_audit_nv_string">
                  <xsl:with-param name="str" select="data/user_device/device_rule/@i" />
                </xsl:call-template>
              </xsl:attribute>
            </Data>
          </Hardware>
          <xsl:call-template name="emitOutcome" />
          <xsl:call-template name="processIncidentals" />
        </Uninstall>
      </xsl:when>
    </xsl:choose>
  </xsl:template>

  <!-- Gather incidental process information -->
  <xsl:template name="processIncidentals">
    <xsl:if test="data/proctitle/proctitle">
      <Data Name="Proctitle">
        <xsl:attribute name="Value" select="data/proctitle/proctitle/@i" />
      </Data>
    </xsl:if>
    <xsl:if test="data/container_id/contid">

      <!--
      Note that one can have multiple comma separated container ids. In detail
      The original field format was "contid=<contid>" for task-associated records and "contid=<contid>[,<contid>[...]]" for network-namespace-associated records.
      The new field format is"contid=<contid>[^<contid>[...]][,<contid>[...]]".
      -->
      <Data Name="ContainerId">
        <xsl:attribute name="Value" select="data/container_id/contid/@i" />
      </Data>
    </xsl:if>
    <xsl:if test="data//cwd">
      <Data Name="cwd">
        <xsl:attribute name="Value" select="data//cwd/@i" />
      </Data>
    </xsl:if>
    <xsl:if test="data//pid">
      <Data Name="pid">
        <xsl:attribute name="Value" select="distinct-values(./data//pid/@i)" />
      </Data>
    </xsl:if>
    <xsl:if test="data//vm-pid">
      <Data Name="vm-pid">
        <xsl:attribute name="Value" select="distinct-values(./data//vm-pid/@i)" />
      </Data>
    </xsl:if>
    <xsl:if test="data//vmpid">
      <Data Name="vmpid">
        <xsl:attribute name="Value" select="distinct-values(./data//vmpid/@i)" />
      </Data>
    </xsl:if>
    <xsl:if test="data/syscall/ppid">
      <Data Name="ppid">
        <xsl:attribute name="Value" select="data/syscall/ppid/@i" />
      </Data>
    </xsl:if>
    <xsl:if test="data//tty">
      <Data Name="tty">
        <xsl:attribute name="Value" select="data//tty/@i" />
      </Data>
    </xsl:if>
    <xsl:if test="data//terminal">
      <Data Name="tty">
        <xsl:attribute name="Value" select="data//terminal/@i" />
      </Data>
    </xsl:if>
    <xsl:if test="data//subj">
      <Data Name="subj">
        <xsl:attribute name="Value" select="data//subj/@i" />
      </Data>
    </xsl:if>
    <xsl:if test="data//ses">
      <Data Name="ses">

        <!-- 20230304: We can have multipel data//ses values -->
        <xsl:attribute name="Value" select="distinct-values(data//ses/@i)" />
      </Data>
    </xsl:if>
    <xsl:if test="data//key">
      <Data Name="filterKey">
        <xsl:attribute name="Value" select="data//key/@i" />
      </Data>
    </xsl:if>
    <xsl:if test="data//addr">
      <Data Name="addr">
        <xsl:attribute name="Value" select="data//addr/@i" />
      </Data>
    </xsl:if>
    <xsl:if test="data//hostname">
      <Data Name="hostname">
        <xsl:attribute name="Value" select="data//hostname/@i" />
      </Data>
    </xsl:if>
    <xsl:if test="data//comm">
      <Data Name="comm">
        <xsl:attribute name="Value" select="distinct-values(data//comm/@i)" />
      </Data>
    </xsl:if>
    <xsl:if test="data//exe">
      <Data Name="exe">
        <xsl:attribute name="Value" select="data//exe/@i" />
      </Data>
    </xsl:if>
    <xsl:if test="data//reason">

      <!-- reason usually has double quotes -->
      <Data Name="reason">
        <xsl:attribute name="Value" select="replace(data//reason/@i,'&#34;', '')" />
      </Data>
    </xsl:if>
    <xsl:if test="data//sig">
      <Data Name="signal">
        <xsl:attribute name="Value" select="data//sig/@i" />
      </Data>
    </xsl:if>
    <xsl:if test="data//rdev">
      <Data Name="rdev">
        <xsl:attribute name="Value" select="data//rdev/@i" />
      </Data>
    </xsl:if>

    <!-- 20221221: Add dev to list -->
    <xsl:if test="data//dev">
      <Data Name="dev">
        <xsl:attribute name="Value" select="data//dev/@i" />
      </Data>
    </xsl:if>
    <xsl:if test="data/capset/cap_pi">
      <Data Name="cap_pi">
        <xsl:attribute name="Value" select="data/capset/cap_pi/@i" />
      </Data>
    </xsl:if>
    <xsl:if test="data/capset/cap_pp">
      <Data Name="cap_pp">
        <xsl:attribute name="Value" select="data/capset/cap_pp/@i" />
      </Data>
    </xsl:if>
    <xsl:if test="data/capset/cap_pe">
      <Data Name="cap_pe">
        <xsl:attribute name="Value" select="data/capset/cap_pe/@i" />
      </Data>
    </xsl:if>

    <!-- Populate the UID's -->
    <xsl:variable name="uidList">
      <xsl:if test="data//auid">
        <xsl:text>AUID:</xsl:text>
        <xsl:value-of select="data//auid/@i" />
      </xsl:if>
      <xsl:if test="data//uid">
        <xsl:text> UID:</xsl:text>
        <xsl:value-of select="data//uid/@i" />
      </xsl:if>
      <xsl:if test="data//gid">
        <xsl:text> GID:</xsl:text>
        <xsl:value-of select="data//gid/@i" />
      </xsl:if>
      <xsl:if test="data//euid">
        <xsl:text> EUID:</xsl:text>
        <xsl:value-of select="data//euid/@i" />
      </xsl:if>
      <xsl:if test="data//suid">
        <xsl:text> SUID:</xsl:text>
        <xsl:value-of select="data//suid/@i" />
      </xsl:if>
      <xsl:if test="data//fsuid">
        <xsl:text> FSUID:</xsl:text>
        <xsl:value-of select="data//fsuid/@i" />
      </xsl:if>
      <xsl:if test="data//egid">
        <xsl:text> EGID:</xsl:text>
        <xsl:value-of select="data//egid/@i" />
      </xsl:if>
      <xsl:if test="data//sgid">
        <xsl:text> SGID:</xsl:text>
        <xsl:value-of select="data//sgid/@i" />
      </xsl:if>
      <xsl:if test="data//fsgid">
        <xsl:text> FSGID:</xsl:text>
        <xsl:value-of select="data//fsgid/@i" />
      </xsl:if>

      <!-- 20230610: Support sauid value -->
      <xsl:if test="data//sauid">
        <xsl:text> SAUID:</xsl:text>
        <xsl:value-of select="data//sauid/@i" />
      </xsl:if>
      <xsl:if test="data//id">
        <xsl:text> ID:</xsl:text>
        <xsl:value-of select="data//id/@i" />
      </xsl:if>
      <xsl:if test="data//grp">
        <xsl:text> GRP:</xsl:text>
        <xsl:value-of select="data//grp/@i" />
      </xsl:if>
    </xsl:variable>
    <xsl:if test="string-length($uidList)>0">
      <Data Name="uidList">
        <xsl:attribute name="Value" select="$uidList" />
      </Data>
    </xsl:if>

    <!-- If a syscall, provide all a* args -->
    <xsl:if test="data/syscall">
      <xsl:variable name="sargs">
        <xsl:if test="data/syscall/a0/@i">
          <xsl:value-of select="concat('a0=', data/syscall/a0/@i)" />
        </xsl:if>
        <xsl:if test="data/syscall/a1/@i">
          <xsl:value-of select="concat(' a1=', data/syscall/a1/@i)" />
        </xsl:if>
        <xsl:if test="data/syscall/a2/@i">
          <xsl:value-of select="concat(' a2=', data/syscall/a2/@i)" />
        </xsl:if>
        <xsl:if test="data/syscall/a3/@i">
          <xsl:value-of select="concat(' a3=', data/syscall/a3/@i)" />
        </xsl:if>
      </xsl:variable>

      <!-- 20221221: Add the syscall itself for those events that are not syscalls -->
      <xsl:if test="string-length(data/syscall/syscall/@i)>0">
        <Data Name="Syscall" Value="{data/syscall/syscall/@i}" />
      </xsl:if>
      <xsl:if test="string-length($sargs)>0">
        <Data Name="SyscallArgs">
          <xsl:attribute name="Value" select="$sargs" />
        </Data>
      </xsl:if>
    </xsl:if>

    <!-- Support FANOTIFY (20230903)
    type=FANOTIFY msg=audit(03/09/23 15:13:36.104:391) : resp=deny 
    where resp can be allow, deny or unknown
    -->
    <xsl:if test="data/fanotify">
      <Data Name="FANotifyResponse" Value="{data/fanotify/resp/@i}" />
    </xsl:if>

    <!-- Add architecture (20210101) -->
    <xsl:if test="data/syscall/arch">
      <Data Name="arch" Value="{data/syscall/arch/@i}" />
    </xsl:if>

    <!-- Add integrity_data (20211017) -->
    <xsl:for-each select="data/integrity_data">
      <xsl:variable name="_ipos" select="position()" />
      <xsl:for-each select="*">
        <Data>
          <xsl:attribute name="Name">
            <xsl:value-of select="concat('IntegrityData', $_ipos, '_', name(.))" />
          </xsl:attribute>
          <xsl:attribute name="Value">
            <xsl:value-of select="@i" />
          </xsl:attribute>
        </Data>
      </xsl:for-each>
    </xsl:for-each>

    <!-- 20221221: Add exit -->
    <xsl:if test="data//exit">
      <Data Name="exit" Value="{data//exit/@i}" />
    </xsl:if>

    <!-- 20230110: Add reset, op -->
    <xsl:if test="data//reset">
      <Data Name="reset" Value="{data//reset/@i}" />
    </xsl:if>
    <xsl:if test="data//op">
      <Data Name="op" Value="{data//op/@i}" />
    </xsl:if>

    <!-- 20230614: Add svc -->
    <xsl:if test="data//avc">
      <Data Name="avc" Value="{data//avc/@i}" />
    </xsl:if>
  </xsl:template>

  <!-- Process Path items as incidentals (for unknown collection) -->
  <xsl:template name="processPathIncidentals">
    <xsl:for-each select="data/path/item">
      <xsl:variable name="_ipos" select="position()" />
      <xsl:for-each select="*">
        <Data>
          <xsl:attribute name="Name">
            <xsl:value-of select="concat('PathItem', $_ipos, '_', name(.))" />
          </xsl:attribute>
          <xsl:attribute name="Value">
            <xsl:value-of select="@i" />
          </xsl:attribute>
        </Data>
      </xsl:for-each>
    </xsl:for-each>
    <xsl:for-each select="data/avc/item">
      <xsl:variable name="_ipos" select="position()" />
      <xsl:for-each select="*">
        <Data>
          <xsl:attribute name="Name">
            <xsl:value-of select="concat('AVCItem', $_ipos, '_', name(.))" />
          </xsl:attribute>
          <xsl:attribute name="Value">
            <xsl:value-of select="@i" />
          </xsl:attribute>
        </Data>
      </xsl:for-each>
    </xsl:for-each>
  </xsl:template>

  <!-- Is this a well known Linux NPE user -->
  <xsl:template name="emitUserId">
    <xsl:param name="_u" as="xs:string" />

    <!-- TODO: This should probably be a dictionary we load elsewhere -->

    <!-- This list is the users from a Centos7 everything install -->

    <!--
    <xsl:variable name="wellKnownLinuxUsers" select="tokenize('brt,adm,amandabackup,apache,avahi,bin,chrony,colord,daemon,dbus,dirsrv,dovecot,dovenull,ftp,games,gdm,geoclue,gluster,gnome-initial-setup,halt,hsqldb,ipaapi,kdcproxy,libstoragemgmt,lp,mail,mysql,named,nfsnobody,nobody,ntp,ods,operator,oprofile,ovirt,pcp,pegasus,pkiuser,polkitd,postfix,postgres,pulse,qemu,radvd,root,rpc,rpcuser,rtkit,saned,sanlock,saslauth,setroubleshoot,shutdown,sshd,sssd,sync,systemd-network,tcpdump,tomcat,tss,unbound,unset,usbmuxd,vdsm
    ', ',')" />
    <xsl:if test="index-of($wellKnownLinuxUsers, $_u)">
    <Type>NPE</Type>
    </xsl:if>
    -->

    <!-- 20240921: Add internally defined _unknown_ user as a NPE user -->

    <!-- 20250427: Use map rather than index 
    <xsl:if test="index-of($evk, $_u) or $_u = '_unknown_'">
    <Type>NPE</Type>
    </xsl:if>
    -->
    <xsl:if test="map:contains($wellKnownNPELinuxUsers, $_u)">
      <Type>NPE</Type>
    </xsl:if>
    <Id>

      <!-- Extract out the uid if we have the form 'unknown(<uid>)' -->

      <!-- 20240510: Depricated in favour of analyze-string solution
      <xsl:choose>
      <xsl:when test="matches($_u, '^unknown\(\d+\)$')">
      <xsl:value-of select="substring-before(substring-after($_u, '('), ')')" />
      </xsl:when>
      <xsl:when test="matches($_u, '.+?\(\d+\)')">
      <xsl:value-of select="substring-before($_u, '(')" />
      </xsl:when>
      <xsl:otherwise>
      <xsl:value-of select="$_u" />
      </xsl:otherwise>
      </xsl:choose>
      -->

      <!-- 20240510: More efficiently parse user names for
      unknown(id)
      name(id)
      everythingelse
      -->
      <xsl:analyze-string select="$_u" regex="^([^\(]+)\((\d+)\)$">
        <xsl:matching-substring>
          <xsl:choose>

            <!-- If we have unknown(id), choose the id part -->
            <xsl:when test="regex-group(1) = 'unknown'">
              <xsl:value-of select="regex-group(2)" />
            </xsl:when>

            <!-- Otherwise choose the name part -->
            <xsl:otherwise>
              <xsl:value-of select="regex-group(1)" />
            </xsl:otherwise>
          </xsl:choose>
        </xsl:matching-substring>
        <xsl:non-matching-substring>
          <xsl:value-of select="$_u" />
        </xsl:non-matching-substring>
      </xsl:analyze-string>
    </Id>
  </xsl:template>

  <!-- Populate outcome element -->
  <xsl:template name="emitOutcome">

    <!-- Determine the outcome status - extracting from res or success values or sig value if we are an abnormal_end or security compute mode action -->
    <xsl:variable name="outcome">
      <xsl:value-of select="./data//res/@i" />
      <xsl:value-of select="./data//success/@i" />
      <xsl:if test="exists(./data/anom_abend) or exists(data/seccomp)">
        <xsl:value-of select="./data//sig/@i" />
      </xsl:if>
    </xsl:variable>

    <!-- Given we can determine outcome, emit failure and the reason. Thus we assume success by default -->
    <xsl:if test="string-length($outcome) > 0 and not(matches($outcome, '^success|^1|^yes') and not(contains(./data/avc/item[1]/avc/@i,'denied')))">
      <Outcome>
        <Success>false</Success>

        <!-- Failure description can come from
        uringop exit key value, 20221219
        syscall exit key value,
        anormal_end reason value,
        combination of signal,
        syscall and code for security compute mode action or
        the selinux result and permissions keys
        -->
        <xsl:variable name="des">
          <xsl:choose>
            <xsl:when test="exists(data/uringop/exit)">
              <xsl:value-of select="replace(data/uringop/exit/@i,'^[^\(]+\((.+)\)','$1')" />
            </xsl:when>
            <xsl:when test="exists(data/syscall/exit)">
              <xsl:value-of select="replace(data/syscall/exit/@i,'^[^\(]+\((.+)\)','$1')" />
            </xsl:when>
            <xsl:when test="exists(data/anom_abend/reason)">
              <xsl:value-of select="replace(data/anom_abend/reason/@i,'&#34;','')" />
            </xsl:when>
            <xsl:when test="exists(data/seccomp)">
              <xsl:value-of select="concat('Signal: ', data/seccomp/sig/@i, ' Syscall: ', data/seccomp/syscall/@i,' Action: ', data/seccomp/code/@i)" />
            </xsl:when>
          </xsl:choose>
          <xsl:for-each select="data/avc/item/avc">
            <xsl:if test="position() = 1">
              <xsl:text> avc:</xsl:text>
            </xsl:if>
            <xsl:value-of select="@i" />
          </xsl:for-each>
        </xsl:variable>
        <xsl:variable name="selinux_err">
          <xsl:if test=".//avc/item and .//avc/item/seresult/@i">
            <xsl:value-of select="concat(.//avc/item/seresult/@i, ' seperms: ', .//avc/item/seperms/@i)" />
          </xsl:if>
        </xsl:variable>
        <xsl:if test="string-length($des) > 0 or string-length($selinux_err) > 0">
          <Description>
            <xsl:value-of select="$des" />
            <xsl:if test="string-length($selinux_err)>0">
              <xsl:value-of select="concat(' (SeLinux: ', $selinux_err, ')')" />
            </xsl:if>
          </Description>
        </xsl:if>
      </Outcome>
    </xsl:if>
  </xsl:template>

  <!-- Emit object owner and modes -->
  <xsl:template name="ownerModes">
    <xsl:param name="_item" />

    <!-- 20221222: The mode attribute can have multiple strings before the mode as per file,suid,755 so get the last value in a csv list -->
    <xsl:variable name="oMode" select="tokenize($_item/mode/@i, ',')[last()]" />

    <!--
    <xsl:variable name="oMode" select="substring-after($_item/mode/@i, ',')" />
    -->
    <Permissions>
      <Permission>

        <!-- In the case where we can't find the user or group (e.g. no such file or directory), we use an '_unknown_' user or group -->
        <xsl:variable name="_id">
          <xsl:choose>
            <xsl:when test="$_item/ouid/@i">
              <xsl:value-of select="$_item/ouid/@i" />
            </xsl:when>
            <xsl:otherwise>_unknown_</xsl:otherwise>
          </xsl:choose>
        </xsl:variable>
        <User>
          <xsl:call-template name="emitUserId">
            <xsl:with-param name="_u" select="$_id" />
          </xsl:call-template>
        </User>
        <xsl:call-template name="fileModes">
          <xsl:with-param name="mode" select="substring($oMode,1,1)" />
        </xsl:call-template>
      </Permission>
      <Permission>

        <!-- In the case where we can't find the user or group (e.g. no such file or directory), we use an '_unknown_' user or group -->
        <xsl:variable name="_id">
          <xsl:choose>
            <xsl:when test="$_item/ogid/@i">
              <xsl:value-of select="$_item/ogid/@i" />
            </xsl:when>
            <xsl:otherwise>_unknown_</xsl:otherwise>
          </xsl:choose>
        </xsl:variable>
        <Group>
          <xsl:call-template name="emitUserId">
            <xsl:with-param name="_u" select="$_id" />
          </xsl:call-template>
        </Group>
        <xsl:call-template name="fileModes">
          <xsl:with-param name="mode" select="substring($oMode,2,1)" />
        </xsl:call-template>
      </Permission>
      <Permission>
        <User>
          <Type>NPE</Type>
          <Id>Other</Id>
        </User>
        <xsl:call-template name="fileModes">
          <xsl:with-param name="mode" select="substring($oMode,3,1)" />
        </xsl:call-template>
      </Permission>
    </Permissions>
  </xsl:template>

  <!-- Form a path -->
  <xsl:template name="genPath">
    <xsl:param name="_fn" />
    <Path>
      <xsl:if test="not(starts-with($_fn, '/'))">
        <xsl:value-of select="replace(concat(./data/cwd/cwd/@i,'/'),'//','/')" />
      </xsl:if>
      <xsl:value-of select="replace($_fn,'//+','/')" />
    </Path>
  </xsl:template>

  <!-- Break out standard Unix octal file modes -->
  <xsl:template name="fileModes">
    <xsl:param name="mode" />
    <xsl:if test="contains('4567',$mode)">
      <Allow>Read</Allow>
    </xsl:if>
    <xsl:if test="contains('2367',$mode)">
      <Allow>Write</Allow>
    </xsl:if>
    <xsl:if test="contains('1357',$mode)">
      <Allow>Execute</Allow>
    </xsl:if>
    <xsl:if test="not(contains('4567',$mode))">
      <Deny>Read</Deny>
    </xsl:if>
    <xsl:if test="not(contains('2367',$mode))">
      <Deny>Write</Deny>
    </xsl:if>
    <xsl:if test="not(contains('1357',$mode))">
      <Deny>Execute</Deny>
    </xsl:if>
  </xsl:template>

  <!-- 20240922: Decode a audit_encode_nv_string(3) hex encoded string -->
  <xsl:template name="decode_audit_nv_string">
    <xsl:param name="str" />
    <xsl:variable name="slen" select="string-length($str)" />
    <xsl:for-each select="1 to ceiling($slen div 2)">
      <xsl:variable name="start" select="(position() - 1) * 2 + 1" />
      <xsl:variable name="decimalValue" select="xs:integer(stroom:hex-to-dec(substring($str, $start, 2)))" />
      <xsl:value-of select="codepoints-to-string($decimalValue)" />
    </xsl:for-each>
  </xsl:template>

  <!-- -->
</xsl:stylesheet>
