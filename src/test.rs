use crate::parser::*;
use crate::types::*;

#[test]
fn parser() {
    // ensure that constant init works
    assert_eq!(format!("--{}--", MessageType::EOE), "--EOE--");
    assert_eq!(format!("--{}--", MessageType(9999)), "--UNKNOWN[9999]--");

    let msg = parse(include_bytes!("testdata/line-eoe.txt"), false).unwrap();
    assert_eq!(msg.ty, MessageType::EOE);
    assert_eq!(
        msg.id,
        EventID {
            timestamp: 1615225617302,
            sequence: 25836
        }
    );

    let msg = parse(include_bytes!("testdata/line-syscall.txt"), false).unwrap();
    assert_eq!(msg.ty, MessageType::SYSCALL);
    assert_eq!(
        msg.id,
        EventID {
            timestamp: 1615114232375,
            sequence: 15558
        }
    );
    assert_eq!(
        msg.body
            .into_iter()
            .map(|(k, v)| format!("{k:?}: {v:?}"))
            .collect::<Vec<_>>(),
        vec!(
            "arch: Num:<0xc000003e>",
            "syscall: Num:<59>",
            "success: Str:<yes>",
            "exit: Num:<0>",
            "a0: Num:<0x63b29337fd18>",
            "a1: Num:<0x63b293387d58>",
            "a2: Num:<0x63b293375640>",
            "a3: Num:<0xfffffffffffff000>",
            "items: Num:<2>",
            "ppid: Num:<10883>",
            "pid: Num:<10884>",
            "auid: Num:<1000>",
            "uid: Num:<0>",
            "gid: Num:<0>",
            "euid: Num:<0>",
            "suid: Num:<0>",
            "fsuid: Num:<0>",
            "egid: Num:<0>",
            "sgid: Num:<0>",
            "fsgid: Num:<0>",
            "tty: Str:<pts1>",
            "ses: Num:<1>",
            "comm: Str:<whoami>",
            "exe: Str:</usr/bin/whoami>",
            "key: Empty",
            "ARCH: Str:<x86_64>",
            "SYSCALL: Str:<execve>",
            "AUID: Str:<user>",
            "UID: Str:<root>",
            "GID: Str:<root>",
            "EUID: Str:<root>",
            "SUID: Str:<root>",
            "FSUID: Str:<root>",
            "EGID: Str:<root>",
            "SGID: Str:<root>",
            "FSGID: Str:<root>",
        )
    );

    let msg = parse(include_bytes!("testdata/line-execve.txt"), false).unwrap();
    assert_eq!(msg.ty, MessageType::EXECVE);
    assert_eq!(
        msg.id,
        EventID {
            timestamp: 1614788539386,
            sequence: 13232
        }
    );
    assert_eq!(
        msg.body
            .into_iter()
            .map(|(k, v)| format!("{k:?}: {v:?}"))
            .collect::<Vec<_>>(),
        vec!("argc: Num:<0>", "a0: Str:<whoami>")
    );

    let msg = parse(include_bytes!("testdata/line-path.txt"), false).unwrap();
    assert_eq!(msg.ty, MessageType::PATH);
    assert_eq!(
        msg.id,
        EventID {
            timestamp: 1614788539386,
            sequence: 13232
        }
    );
    assert_eq!(
        msg.body
            .into_iter()
            .map(|(k, v)| format!("{k:?}: {v:?}"))
            .collect::<Vec<_>>(),
        vec!(
            "item: Num:<0>",
            "name: Str:</usr/bin/whoami>",
            "inode: Num:<261214>",
            "dev: Str:<ca:03>",
            "mode: Num:<0o100755>",
            "ouid: Num:<0>",
            "ogid: Num:<0>",
            "rdev: Str:<00:00>",
            "nametype: Str:<NORMAL>",
            "cap_fp: Num:<0x0>",
            "cap_fi: Num:<0x0>",
            "cap_fe: Num:<0>",
            "cap_fver: Num:<0x0>",
        )
    );

    let msg = parse(include_bytes!("testdata/line-path-enriched.txt"), false).unwrap();
    assert_eq!(msg.ty, MessageType::PATH);
    assert_eq!(
        msg.id,
        EventID {
            timestamp: 1615113648978,
            sequence: 15219
        }
    );
    assert_eq!(
        msg.body
            .into_iter()
            .map(|(k, v)| format!("{k:?}: {v:?}"))
            .collect::<Vec<_>>(),
        vec!(
            "item: Num:<1>",
            "name: Str:</lib64/ld-linux-x86-64.so.2>",
            "inode: Num:<262146>",
            "dev: Str:<ca:03>",
            "mode: Num:<0o100755>",
            "ouid: Num:<0>",
            "ogid: Num:<0>",
            "rdev: Str:<00:00>",
            "nametype: Str:<NORMAL>",
            "cap_fp: Num:<0x0>",
            "cap_fi: Num:<0x0>",
            "cap_fe: Num:<0>",
            "cap_fver: Num:<0x0>",
            "OUID: Str:<root>",
            "OGID: Str:<root>",
        )
    );

    let msg = parse(include_bytes!("testdata/line-user-acct.txt"), false).unwrap();
    assert_eq!(msg.ty, MessageType::USER_ACCT);
    assert_eq!(
        msg.id,
        EventID {
            timestamp: 1615113648981,
            sequence: 15220
        }
    );
    assert_eq!(msg.body.into_iter().map(|(k,v)| format!("{k:?}: {v:?}")).collect::<Vec<_>>(),
                   vec!("pid: Num:<9460>",
                        "uid: Num:<1000>",
                        "auid: Num:<1000>",
                        "ses: Num:<1>",
                        "msg: Str:<op=PAM:accounting grantors=pam_permit acct=\"user\" exe=\"/usr/bin/sudo\" hostname=? addr=? terminal=/dev/pts/1 res=success>",
                        "UID: Str:<user>",
                        "AUID: Str:<user>",
                   ));

    let msg = parse(include_bytes!("testdata/line-unknown.txt"), false).unwrap();
    assert_eq!(msg.ty, MessageType::BPF);
    assert_eq!(
        msg.id,
        EventID {
            timestamp: 1626883065201,
            sequence: 216697
        }
    );

    let msg = parse(include_bytes!("testdata/line-avc-denied.txt"), false).unwrap();
    assert_eq!(msg.ty, MessageType::AVC);
    assert_eq!(
        msg.body
            .into_iter()
            .map(|(k, v)| format!("{k:?}: {v:?}"))
            .collect::<Vec<_>>(),
        vec!(
            "pid: Num:<15381>",
            "comm: Str:<laurel>",
            "capability: Num:<7>",
            "scontext: Str:<system_u:system_r:auditd_t:s0>",
            "tcontext: Str:<system_u:system_r:auditd_t:s0>",
            "tclass: Str:<capability>",
            "permissive: Num:<1>",
            "denied: List:<setuid>",
        )
    );

    let msg = parse(include_bytes!("testdata/line-avc-granted.txt"), false).unwrap();
    assert_eq!(msg.ty, MessageType::AVC);
    assert_eq!(
        msg.body
            .into_iter()
            .map(|(k, v)| format!("{k:?}: {v:?}"))
            .collect::<Vec<_>>(),
        vec!(
            "pid: Num:<11209>",
            "comm: Str:<tuned>",
            "scontext: Str:<system_u:system_r:tuned_t:s0>",
            "tcontext: Str:<system_u:object_r:security_t:s0>",
            "tclass: Str:<security>",
            "granted: List:<setsecparam>",
        )
    );

    let msg = parse(include_bytes!("testdata/line-netlabel.txt"), false).unwrap();
    assert_eq!(msg.ty, MessageType::MAC_UNLBL_ALLOW);
    assert_eq!(
        msg.body
            .into_iter()
            .map(|(k, v)| format!("{k:?}: {v:?}"))
            .collect::<Vec<_>>(),
        vec!(
            "auid: Num:<0>",
            "ses: Num:<0>",
            // FIXME: strings should be numbers
            "unlbl_accept: Str:<1>",
            "old: Str:<0>",
            "AUID: Str:<root>",
            "netlabel: Empty",
        )
    );

    let msg = parse(include_bytes!("testdata/line-broken-subj1.txt"), false).unwrap();
    assert_eq!(
        msg.body
            .into_iter()
            .map(|(k, v)| format!("{k:?}: {v:?}"))
            .collect::<Vec<_>>(),
        vec!(
            "arch: Num:<0xc000003e>",
            "syscall: Num:<59>",
            "success: Str:<yes>",
            "exit: Num:<0>",
            "a0: Num:<0x55b26d44a6a0>",
            "a1: Num:<0x55b26d44a878>",
            "a2: Num:<0x55b26d44a8e8>",
            "a3: Num:<0x7faeccab5850>",
            "items: Num:<2>",
            "ppid: Num:<659>",
            "pid: Num:<661>",
            "auid: Num:<4294967295>",
            "uid: Num:<0>",
            "gid: Num:<0>",
            "euid: Num:<0>",
            "suid: Num:<0>",
            "fsuid: Num:<0>",
            "egid: Num:<0>",
            "sgid: Num:<0>",
            "fsgid: Num:<0>",
            "tty: Str:<(none)>",
            "ses: Num:<4294967295>",
            "comm: Str:<dhclient>",
            "exe: Str:</sbin/dhclient>",
            "subj: Str:</{,usr/}sbin/dhclient>",
            "key: Empty",
        )
    );

    let msg = parse(include_bytes!("testdata/line-broken-subj2.txt"), false).unwrap();
    assert_eq!(
        msg.body
            .into_iter()
            .map(|(k, v)| format!("{k:?}: {v:?}"))
            .collect::<Vec<_>>(),
        vec!(
            "arch: Num:<0xc000003e>",
            "syscall: Num:<49>",
            "success: Str:<yes>",
            "exit: Num:<0>",
            "a0: Num:<0x15>",
            "a1: Num:<0x55c5e046e264>",
            "a2: Num:<0x1c>",
            "a3: Num:<0x7ffc8fab77ec>",
            "items: Num:<0>",
            "ppid: Num:<1899774>",
            "pid: Num:<1899780>",
            "auid: Num:<4294967295>",
            "uid: Num:<0>",
            "gid: Num:<0>",
            "euid: Num:<0>",
            "suid: Num:<0>",
            "fsuid: Num:<0>",
            "egid: Num:<0>",
            "sgid: Num:<0>",
            "fsgid: Num:<0>",
            "tty: Str:<(none)>",
            "ses: Num:<4294967295>",
            "comm: Str:<ntpd>",
            "exe: Str:</usr/sbin/ntpd>",
            "subj: Str:<=/usr/sbin/ntpd (enforce)>",
            "key: Empty",
        )
    );

    let msg = parse(include_bytes!("testdata/line-broken-avc-info.txt"), false).unwrap();
    assert_eq!(
        msg.body
            .into_iter()
            .map(|(k, v)| format!("{k:?}: {v:?}"))
            .collect::<Vec<_>>(),
        vec!(
            "apparmor: Str:<STATUS>",
            "operation: Str:<profile_replace>",
            "info: Str:<same as current profile, skipping>",
            "profile: Str:<unconfined>",
            "name: Str:<snap-update-ns.amazon-ssm-agent>",
            "pid: Num:<3981295>",
            "comm: Str:<apparmor_parser>",
        )
    );

    parse(include_bytes!("testdata/line-daemon-end.txt"), false).unwrap();
    parse(include_bytes!("testdata/line-netfilter.txt"), false).unwrap();
    parse(include_bytes!("testdata/line-anom-abend.txt"), false).unwrap();
    parse(include_bytes!("testdata/line-anom-abend-2.txt"), false).unwrap();
    parse(include_bytes!("testdata/line-user-auth.txt"), false).unwrap();
    parse(include_bytes!("testdata/line-sockaddr-unix.txt"), false).unwrap();
    parse(include_bytes!("testdata/line-sockaddr-unix-2.txt"), false).unwrap();
    parse(include_bytes!("testdata/line-user-auth-2.txt"), false).unwrap();
    parse(include_bytes!("testdata/line-mac-policy-load.txt"), false).unwrap();
    parse(include_bytes!("testdata/line-tty.txt"), false).unwrap();
}

#[test]
fn breakage_sockaddr_unknown() {
    parse(
        include_bytes!("testdata/line-sockaddr-unknown-1.txt"),
        false,
    )
    .expect("can't parse line-sockaddr-unknown-1.txt");
    parse(
        include_bytes!("testdata/line-sockaddr-unknown-2.txt"),
        false,
    )
    .expect("can't parse line-sockaddr-unknown-2.txt");
    parse(
        include_bytes!("testdata/line-sockaddr-unknown-3.txt"),
        false,
    )
    .expect("can't parse line-sockaddr-unknown-3.txt");
}
