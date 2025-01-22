use crate::*;

#[cfg(feature = "serde")]
use serde_test::{assert_ser_tokens, Token};

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
    assert_eq!(
        msg.body
            .into_iter()
            .map(|(k, v)| format!("{k:?}: {v:?}"))
            .collect::<Vec<_>>(),
        vec!(
            "pid: Num:<9460>",
            "uid: Num:<1000>",
            "auid: Num:<1000>",
            "ses: Num:<1>",
	    "msg: Map:<op=Str:<PAM:accounting> grantors=Str:<pam_permit> acct=Str:<user> exe=Str:</usr/bin/sudo> hostname=Empty addr=Empty terminal=Str:</dev/pts/1> res=Str:<success>>",
            "UID: Str:<user>",
            "AUID: Str:<user>",
        )
    );

    let msg = Parser {
        enriched: false,
        split_msg: false,
    }
    .parse(include_bytes!("testdata/line-user-acct.txt"))
    .unwrap();
    assert_eq!(
        msg.body
            .into_iter()
            .map(|(k, v)| format!("{k:?}: {v:?}"))
            .collect::<Vec<_>>(),
        vec!(
            "pid: Num:<9460>",
            "uid: Num:<1000>",
            "auid: Num:<1000>",
            "ses: Num:<1>",
            r#"msg: Str:<op=PAM:accounting grantors=pam_permit acct="user" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/1 res=success>"#,
        )
    );

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
fn test_msg_kv() {
    let p = Parser {
        split_msg: true,
        ..Parser::default()
    };
    for line in [
        &include_bytes!("testdata/line-acct-lock.txt")[..],
        &include_bytes!("testdata/line-add-group.txt")[..],
        &include_bytes!("testdata/line-add-user.txt")[..],
        &include_bytes!("testdata/line-chgrp-id.txt")[..],
        &include_bytes!("testdata/line-cred-acq.txt")[..],
        &include_bytes!("testdata/line-cred-disp.txt")[..],
        &include_bytes!("testdata/line-cred-refr.txt")[..],
        &include_bytes!("testdata/line-crypto-key-user.txt")[..],
        &include_bytes!("testdata/line-crypto-session.txt")[..],
        &include_bytes!("testdata/line-crypto-param-change-user.txt")[..],
        &include_bytes!("testdata/line-daemon-end-2.txt")[..],
        &include_bytes!("testdata/line-del-group.txt")[..],
        &include_bytes!("testdata/line-del-user.txt")[..],
        &include_bytes!("testdata/line-grp-mgmt.txt")[..],
        &include_bytes!("testdata/line-software-update.txt")[..],
        &include_bytes!("testdata/line-user-acct.txt")[..],
        &include_bytes!("testdata/line-user-auth.txt")[..],
        &include_bytes!("testdata/line-user-auth-2.txt")[..],
        &include_bytes!("testdata/line-user-chauthtok.txt")[..],
        &include_bytes!("testdata/line-user-end.txt")[..],
        &include_bytes!("testdata/line-user-err.txt")[..],
        &include_bytes!("testdata/line-user-login.txt")[..],
        &include_bytes!("testdata/line-user-logout.txt")[..],
        &include_bytes!("testdata/line-user-mgmt.txt")[..],
        &include_bytes!("testdata/line-user-role-change.txt")[..],
        &include_bytes!("testdata/line-user-start.txt")[..],
        &include_bytes!("testdata/line-usys-config.txt")[..],
        &include_bytes!("testdata/line-user-avc-1.txt")[..],
        &include_bytes!("testdata/line-user-avc-2.txt")[..],
        &include_bytes!("testdata/line-user-selinux-err.txt")[..],
    ] {
        let m = p.parse(line).unwrap();
        println!("{:?}", &m);
        let msg = m
            .body
            .get("msg")
            .unwrap_or_else(|| panic!("{}: Field msg not found", m.id));
        match msg {
            Value::Map(_) => {}
            Value::Str(_, _) => panic!("{}: Field msg was parsed as string", m.id),
            _ => panic!("{}: Field msg was parsed as something else", m.id),
        }
    }
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

#[test]
#[cfg(feature = "serde")]
fn serde_messagetype() {
    assert_ser_tokens(&MessageType::SYSCALL, &[Token::String("SYSCALL")]);
    assert_ser_tokens(&MessageType(20000), &[Token::String("UNKNOWN[20000]")]);
}

#[test]
#[cfg(feature = "serde")]
fn serde_key() {
    assert_ser_tokens(&Key::Name(b"foo"[..].into()), &[Token::String("foo")]);
    assert_ser_tokens(&Key::NameUID(b"euid"[..].into()), &[Token::String("euid")]);
    assert_ser_tokens(&Key::NameGID(b"egid"[..].into()), &[Token::String("egid")]);
    assert_ser_tokens(&Key::Common(Common::Arch), &[Token::String("arch")]);
    assert_ser_tokens(
        &Key::NameTranslated(b"foo"[..].into()),
        &[Token::String("FOO")],
    );
    assert_ser_tokens(&Key::Arg(1, None), &[Token::String("a1")]);
    assert_ser_tokens(&Key::Arg(2, Some(3)), &[Token::String("a2[3]")]);
    assert_ser_tokens(&Key::ArgLen(2), &[Token::String("a2_len")]);
    assert_ser_tokens(&Key::Literal("foo"), &[Token::String("foo")]);
}

#[test]
#[cfg(feature = "serde")]
fn serde_value() {
    assert_ser_tokens(&Value::Empty, &[Token::None]);
    for q in &[Quote::None, Quote::Single, Quote::Double] {
        assert_ser_tokens(&Value::Str(&b"foo"[..], *q), &[Token::Bytes(b"foo")]);
    }
    assert_ser_tokens(
        &Value::Str(&b"foo"[..], Quote::Braces),
        &[Token::Bytes(b"{foo}")],
    );

    assert_ser_tokens(&Value::Number(Number::Hex(16)), &[Token::String("0x10")]);
    assert_ser_tokens(&Value::Number(Number::Oct(16)), &[Token::String("0o20")]);
    assert_ser_tokens(&Value::Number(Number::Dec(16)), &[Token::I64(16)]);

    assert_ser_tokens(
        &Value::List(vec![]),
        &[Token::Seq { len: Some(0) }, Token::SeqEnd],
    );
    assert_ser_tokens(
        &Value::List(vec![
            Value::from("foo"),
            Value::from("bar"),
            Value::from("baz"),
            Value::from(42),
        ]),
        &[
            Token::Seq { len: Some(4) },
            Token::Bytes(b"foo"),
            Token::Bytes(b"bar"),
            Token::Bytes(b"baz"),
            Token::I64(42),
            Token::SeqEnd,
        ],
    );
}

#[test]
#[cfg(feature = "serde")]
fn serde_message() {
    let msg = parse(include_bytes!("testdata/line-eoe.txt"), false).unwrap();
    assert_ser_tokens(&msg.body, &[Token::Map { len: Some(0) }, Token::MapEnd]);

    let msg = parse(include_bytes!("testdata/line-execve.txt"), false).unwrap();
    assert_ser_tokens(
        &msg.body,
        &[
            Token::Map { len: Some(2) },
            Token::String("argc"),
            Token::I64(0),
            Token::String("a0"),
            Token::Bytes(b"whoami"),
            Token::MapEnd,
        ],
    );
}

#[test]
#[should_panic]
fn parse_uringop() {
    let msg = parse(include_bytes!("testdata/line-uringop.txt"), false).unwrap();
    println!("{msg:?}");
    let v = msg
        .body
        .get("uring_op")
        .unwrap_or_else(|| panic!("{}: uring_op not found", msg.id));
    assert_eq!(*v, Value::Number(Number::Dec(18)));
}

#[test]
#[should_panic]
fn parse_bpf() {
    let msg = parse(include_bytes!("testdata/line-bpf.txt"), false).unwrap();
    println!("{msg:?}");
    let v = msg
        .body
        .get("prog-id")
        .unwrap_or_else(|| panic!("{}: prog-id not found", msg.id));
    assert_eq!(*v, Value::Number(Number::Dec(75)));
}
