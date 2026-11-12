#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Compare complete UDP payloads with the pinned Java reference methods.

The original packet builders, checksum, CRC, ror and MD5 code are compiled
from a separate reference checkout. Only randomness and GUI dependencies
are replaced. No packet fields are ignored or normalized in comparison.
"""
import argparse
import hashlib
import json
import random
import re
import subprocess
import tempfile
from pathlib import Path

REFERENCE_COMMIT = '2ba09ce24041c4ab7021ddbc07a366e9ae3e1c5d'
SOURCE_PATH = Path('jlu-drcom-java/src/main/java/com/youthlin/jlu/drcom')


def method(source, name):
    """Extract a method verbatim, ignoring braces inside comments/strings."""
    mask = re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*.*?\*/',
                  lambda m: ' ' * len(m[0]), source, flags=re.S)
    match = re.search(r'private\s+(?:boolean|byte\[\])\s+' + name + r'\([^)]*\)[^{]*\{', mask)
    if not match:
        raise ValueError(f'Reference method not found: {name}')
    depth = 1
    end = match.end()
    while depth:
        depth += (mask[end] == '{') - (mask[end] == '}')
        end += 1
    return source[match.start():end]


JAVA_HARNESS = r'''
import com.youthlin.jlu.drcom.util.ByteUtil;
import com.youthlin.jlu.drcom.util.MD5;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

public class ReferencePackets {
    private String username, password;
    private HostInfo hostInfo;
    private byte[] salt, clientIp, tail1, tail2, keepAliveVer;
    private final byte[] md5a = new byte[16];
    private int count;
    static class HostInfo {
        byte[] mac; String hostname;
        byte[] getMacBytes() { return mac; }
        String getHostname() { return hostname; }
    }
    static byte[] hex(String s) { return HexFormat.of().parseHex(s); }
    static String ascii(String s) { return new String(hex(s), StandardCharsets.US_ASCII); }
    static void emit(String type, byte[] data) {
        System.out.println(type + " " + HexFormat.of().formatHex(data));
    }
    public static void main(String[] args) throws Exception {
        BufferedReader input = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        String line;
        while ((line=input.readLine()) != null) {
            String[] f=line.split(" ");
            ReferencePackets p=new ReferencePackets();
            p.username=ascii(f[0]); p.password=ascii(f[1]);
            p.hostInfo=new HostInfo(); p.hostInfo.mac=hex(f[2]); p.hostInfo.hostname=ascii(f[5]);
            p.salt=hex(f[3]); p.clientIp=hex(f[4]);
            byte[] ver=hex(f[6]), tail=hex(f[8]);
            p.keepAliveVer=new byte[]{(byte)0xdc, 0x02}; p.tail2=new byte[4];
            ByteUtil.seed(Long.parseLong(f[9]));
            int cycles=Integer.parseInt(f[10]), challenge=Integer.parseInt(f[11]);
            p.count=Integer.parseInt(f[12]);
            emit("challenge", p.makeChallengePacket(challenge-2));
            emit("login", p.makeLoginPacket());
            p.tail1=hex(f[7]);
            for (int i=0;i<cycles;i++) {
                emit("keep38", p.makeKeepPacket38());
                p.keepAliveVer=ver;
                if (p.count % 21 == 0) emit("extra", p.makeKeepPacket40(1,true));
                emit("keep40_1", p.makeKeepPacket40(1,false));
                p.tail2=tail;
                emit("keep40_2", p.makeKeepPacket40(2,false));
            }
            emit("logout_challenge", p.makeChallengePacket(challenge-1));
            emit("logout", p.makeLogoutPacket());
            System.out.println("end");
        }
    }
    // ORIGINAL_METHODS
}
'''


def compile_reference(checkout, output, javac):
    commit = subprocess.check_output(['git', '-C', str(checkout), 'rev-parse', 'HEAD'], text=True).strip()
    if commit != REFERENCE_COMMIT:
        raise ValueError(f'Expected reference {REFERENCE_COMMIT}, got {commit}')
    subprocess.run(['git', '-C', str(checkout), 'diff', '--exit-code', 'HEAD', '--', str(SOURCE_PATH)],
                   check=True, stdout=subprocess.DEVNULL)
    source = checkout / SOURCE_PATH
    task = (source / 'task/DrcomTask.java').read_text()
    methods = '\n'.join(method(task, name) for name in
                        ['makeLoginPacket', 'makeKeepPacket38', 'makeKeepPacket40', 'makeLogoutPacket'])
    # Preserve the reference challenge initializer verbatim; omit socket I/O.
    initializer = re.search(r'byte\[\] buf = (\{.*?\});', method(task, 'challenge'), re.S)[1]
    methods += '\nprivate byte[] makeChallengePacket(int tryTimes) { byte[] buf = ' + initializer + '; return buf; }\n'
    (output / 'ReferencePackets.java').write_text(JAVA_HARNESS.replace('// ORIGINAL_METHODS', methods))
    byte_util = (source / 'util/ByteUtil.java').read_text()
    byte_util = byte_util.replace(
        'private static final Random random = new Random(System.currentTimeMillis());',
        'private static int randomState; public static void seed(long seed) { randomState=(int)seed; }')
    byte_util = byte_util.replace('return (byte) random.nextInt();',
                                 'randomState=randomState*1664525+1013904223; return (byte)(randomState >>> 24);')
    (output / 'ByteUtil.java').write_text(byte_util)
    (output / 'MD5.java').write_text((source / 'util/MD5.java').read_text())
    subprocess.run([javac, '-encoding', 'UTF-8', '-d', str(output),
                    *map(str, output.glob('*.java'))], check=True, timeout=60)


def fixtures():
    rng = random.Random(0x4A4C5544)
    cases = []

    def case(pass_len, cycles=12, count=0, challenge=2, user_len=None):
        # Includes spaces, punctuation, maximum field sizes, zero/high MAC bytes.
        chars = bytes(range(32, 127))
        user = bytes(rng.choice(chars) for _ in range(user_len or rng.randint(1, 36)))
        password = bytes(rng.choice(chars) for _ in range(pass_len))
        binary = [rng.randbytes(n) for n in [6, 4, 4]]
        hostname = bytes(rng.choice(chars) for _ in range(rng.randint(1, 32)))
        fields = [user, password, *binary, hostname, rng.randbytes(2), rng.randbytes(16), rng.randbytes(4)]
        return ' '.join([*(x.hex() for x in fields), str(rng.getrandbits(32)), str(cycles), str(challenge), str(count)])

    for length in range(1, 17):
        for _ in range(4):
            cases.append(case(length))
    for _ in range(128):
        cases.append(case(rng.randint(1, 16), cycles=rng.randint(0, 35)))
    for count in [0, 252, 255, 65535]:
        cases.append(case(16, cycles=1000, count=count, challenge=255, user_len=36))
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference-dir', type=Path, required=True)
    parser.add_argument('--packet-dump', type=Path, required=True)
    parser.add_argument('--javac', default='javac')
    parser.add_argument('--java', default='java')
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    cases = fixtures()
    data = '\n'.join(cases) + '\n'
    with tempfile.TemporaryDirectory(prefix='drcom-reference-') as tmp:
        compile_reference(args.reference_dir.resolve(), Path(tmp), args.javac)
        expected = subprocess.check_output([args.java, '-Dfile.encoding=UTF-8', '-cp', tmp, 'ReferencePackets'],
                                           input=data, text=True, timeout=60)
        actual = subprocess.check_output([str(args.packet_dump.resolve())], input=data, text=True, timeout=60)
    expected_lines, actual_lines = expected.splitlines(), actual.splitlines()
    case_number = 0
    for index, (want, got) in enumerate(zip(expected_lines, actual_lines)):
        if want != got:
            raise AssertionError(f'case={case_number}, transcript line={index}\nfixture={cases[case_number]}\n'
                                 f'Java: {want}\nC:    {got}')
        case_number += want == 'end'
    if len(expected_lines) != len(actual_lines) or case_number != len(cases):
        raise AssertionError('Transcript length/case count differs')
    report = {'reference_commit': REFERENCE_COMMIT, 'cases': len(cases),
              'packets': len(actual_lines)-len(cases), 'mismatches': 0,
              'transcript_sha256': hashlib.sha256(actual.encode()).hexdigest(),
              'fixtures_sha256': hashlib.sha256(data.encode()).hexdigest()}
    if args.report:
        args.report.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
