#!/bin/python3
import glob
import hashlib
import io
import os
import pickle
import re
import struct
import subprocess
import sys
import tempfile
import zlib

def sha1_path(path):
    with open(path, 'rb') as f:
        return sha1_file(f)
def sha1_file(f):
    hasher = hashlib.sha1()
    BLOCKSIZE=65536
    buf = f.read(BLOCKSIZE)
    while len(buf) > 0:
        hasher.update(buf)
        buf = f.read(BLOCKSIZE)
    return hasher.digest()
def sha1_directory(d):
    return subprocess.getoutput("find {} -type f | sort | xargs sha1sum | cut -f1 -d' ' | sha1sum | cut -f1 -d' '".format(d))

def copy_write(fr, to):
    BLOCKSIZE=65536
    buf = fr.read(BLOCKSIZE)
    while len(buf) > 0:
        to.write(buf)
        buf = fr.read(BLOCKSIZE)

PRINTABLE_TYPES = {
    1: 'commit',
    2: 'tree',
    3: 'blob',
    4: 'tag',
    6: 'delta',
}

def git_hash(t, b):
    buf = io.BytesIO()
    buf.write(bytes(PRINTABLE_TYPES[t], encoding='ascii'))
    buf.write(b' ')
    buf.write(bytes(str(len(b)), encoding='ascii'))
    buf.write(b'\0')
    buf.write(b)
    buf.seek(0)
    return hashlib.sha1(buf.getbuffer()).hexdigest()

def decompress(f):
    do = zlib.decompressobj()
    compressed_start = f.tell()
    decompressed = io.BytesIO()

    BLOCKSIZE=65536
    buf = f.read(BLOCKSIZE)
    decompressed.write(do.decompress(buf))
    while len(buf) > 0 and not do.eof:
        buf = f.read(BLOCKSIZE)
        decompressed.write(do.decompress(buf))
    compressed_length = f.tell() - compressed_start - len(do.unused_data)
    f.seek(compressed_start + compressed_length)
    return decompressed.getvalue(), compressed_length
    

class MismatchHashException(Exception):
    def __init__(self, rel_path, actual_sha, expected_sha):
        super(MismatchHashException, self).__init__("Unexpected hash {} for file {}, expected {}".format(actual_sha, rel_path, expected_sha))

class MissingFileException(Exception):
    def __init__(self, rel_path, is_directory):
        if is_directory:
            message = "Expected to see directory {}".format(rel_path)
        else:
            message = "Expected to see file {}".format(rel_path)
        super(MissingFileException, self).__init__(message)

class UnexpectedFileException(Exception):
    def __init__(self, rel_path, is_directory):
        if is_directory:
            message = "Found unexpected directory {}".format(rel_path)
        else:
            message = "Found file {} which this program does not know how to parse".format(rel_path)
        super(UnexpectedFileException, self).__init__(message)

class RepoBase():
    DIRECTORY_SHA = "DIRECTORY"
    EXPECTED_STATIC_FILES = {
        'branches': DIRECTORY_SHA,
        'hooks': DIRECTORY_SHA,
        'info': DIRECTORY_SHA,
        'objects': DIRECTORY_SHA,
        'objects/info': DIRECTORY_SHA,
        'objects/pack': DIRECTORY_SHA,
        'refs': DIRECTORY_SHA,
        'refs/heads': DIRECTORY_SHA,
        'refs/tags': DIRECTORY_SHA,
        'description': bytes(bytearray.fromhex('9635f1b7e12c045212819dd934d809ef07efa2f4')),
        'hooks/applypatch-msg.sample': bytes(bytearray.fromhex('4de88eb95a5e93fd27e78b5fb3b5231a8d8917dd')),
        'hooks/commit-msg.sample': bytes(bytearray.fromhex('ee1ed5aad98a435f2020b6de35c173b75d9affac')),
        'hooks/fsmonitor-watchman.sample': {bytes(bytearray.fromhex('f7c0aa40cb0d620ff0bca3efe3521ec79e5d7156')), None},
        'hooks/post-update.sample': bytes(bytearray.fromhex('b614c2f63da7dca9f1db2e7ade61ef30448fc96c')),
        'hooks/pre-applypatch.sample': bytes(bytearray.fromhex('f208287c1a92525de9f5462e905a9d31de1e2d75')),
        'hooks/pre-commit.sample': {bytes(bytearray.fromhex('33729ad4ce51acda35094e581e4088f3167a0af8')), bytes(bytearray.fromhex('36aed8976dcc08b5076844f0ec645b18bc37758f'))},
        'hooks/prepare-commit-msg.sample': {bytes(bytearray.fromhex('2584806ba147152ae005cb675aa4f01d5d068456')), bytes(bytearray.fromhex('2b6275eda365cad50d167fe3a387c9bc9fedd54f'))},
        'hooks/pre-push.sample': bytes(bytearray.fromhex('5c8518bfd1d1d3d2c1a7194994c0a16d8a313a41')),
        'hooks/pre-rebase.sample': {bytes(bytearray.fromhex('288efdc0027db4cfd8b7c47c4aeddba09b6ded12')), bytes(bytearray.fromhex('18be3eb275c1decd3614e139f5a311b75f1b0ab8'))},
        'hooks/pre-receive.sample': bytes(bytearray.fromhex('705a17d259e7896f0082fe2e9f2c0c3b127be5ac')),
        'hooks/update.sample': bytes(bytearray.fromhex('e729cd61b27c128951d139de8e7c63d1a3758dde')),
        'info/exclude': bytes(bytearray.fromhex('c879df015d97615050afa7b9641e3352a1e701ac')),
    }

    def __init__(self, store=None):
        self.my_blobs = set()
        self.store = store if store is not None else {}
        self.working_dir = tempfile.TemporaryDirectory()

    def generate_index(self, f):
        pack_path = os.path.join(self.working_dir.name, 'a.pack')
        index_path = os.path.join(self.working_dir.name, 'a.idx')
        with open(pack_path, 'wb') as f2:
            copy_write(f, f2)
        with open(os.devnull, 'w') as FNULL:
            subprocess.call(["git", "index-pack", pack_path])
        os.remove(pack_path)
        index_file = open(index_path, 'rb')
        os.remove(index_path)
        return index_file

    def store_blob(self, b):
        h = hashlib.sha1(b).digest()
        if h in self.store:
            assert self.store[h] == b, "Two distinct blobs stored with the same hash (collision): {}".format(h)
        else:
            self.store[h] = b
        self.my_blobs.add(h)
        return h

    def store_bloblist(self, blobs):
        hs = []
        for blob in blobs:
            hs.append(self.store_blob(blob))
        return self.store_blob(b''.join(hs))

    def load_blob(self, h):
        b = self.store[h]
        assert h in self.my_blobs
        return b

    def load_bloblist(self, h):
        lst = self.load_blob(h)
        blobs = []
        digest_size = hashlib.sha1().digest_size
        assert len(lst) % digest_size == 0, "Hex digest list is the wrong size"
        for x in range(0, len(lst), digest_size):
            h = lst[x:x+digest_size]
            b = self.load_blob(h)
            blobs.append(b)


class RepoWriter(RepoBase):
    def __init__(self, store=None):
        super(RepoWriter, self).__init__(store=store)
        self.expected_blobs = {}
        self.my_blobs = set()

        for path in glob.glob('expected/*'):
            with open(path, 'rb') as f:
                b = f.read()
                h = hashlib.sha1(b).digest()
                self.expected_blobs[h] = b

    @classmethod
    def unserialize(cls, f, store=None):
        parser = RepoWriter()
        serialized_store = pickle.load(f)
        parser.my_blobs = set(serialized_store.keys())
        if store:
            parser.store = store
        else:
            parser.store = serialized_store
        parser.output = pickle.load(f)
        return parser

    def unparse(self, extract_path):
        self.base = extract_path
        for rel_path, (action, *args) in self.output.items():
            if hasattr(self, action):
                getattr(self, action)(*args)
            else:
                raise Exception("Unexpected output action {}".format(action))

    @classmethod
    def unparse_object_header(cls, t, size):
        header = [(size & 0x0f) | (t << 4)]
        size = size >> 4
        while size > 0:
            c = (size & 0x7f) 
            header.append(c)
            size = size >> 7
        header = bytes(header)
        header = bytes(x | 0x80 for x in header[:-1]) + header[-1:]
        return header

    def write_pack(self, objects, f):
        f.write(b'PACK')
        f.write(struct.pack(">i", 2))
        f.write(struct.pack(">i", len(objects)))
        for o in objects:
            t, obj = o
            header = self.unparse_object_header(t, len(obj))
            f.write(header)
            f.write(obj)
        f.seek(0)
        self_sha = self.sha1_file(f)
        f.seek(0)
        f.write(self_sha)

    def unstore_unchanged(self, rel_path, sha):
        abs_path = os.path.join(self.base, rel_path)
        with open(abs_path, 'wb') as f:
            f.write(self.load_blob(sha))

    def unstore_directory(self, rel_path):
        abs_path = os.path.join(self.base, rel_path)
        os.mkdir(abs_path)

    def unstore_expected_directory(self, rel_path):
        abs_path = os.path.join(self.base, rel_path)
        os.mkdir(abs_path)

    def unstore_expected_file(self, rel_path, sha):
        abs_path = os.path.join(self.base, rel_path)
        with open(abs_path, 'wb') as f:
            f.write(self.expected_blobs[sha])

    def unstore_generated_index(self, rel_path, rel_from, sha):
        abs_path = os.path.join(self.base, rel_path)
        abs_from_file = os.path.join(self.base, rel_from)
        assert os.path.exists(abs_from_file), "Generated index file relies on non-existent packfile: {}".format(from_file)
        with open(abs_from_file, 'rb') as f:
            index_file = self.generate_index(f)
        assert sha1_file(index_file) == sha, "Generated index file had wrong hash: {}".format(rel_path)
        index_file.seek(0)
        with open(abs_path, 'wb') as f:
            copy_write(index_file, f)
        index_file.close()

class RepoReader(RepoBase):
    PARSED_FILES = {
        'HEAD': 'store_unchanged',
        'config': 'store_unchanged',
        'packed-refs': 'store_unchanged',
        'info/refs': 'store_unchanged',
        'objects/info/packs': 'store_unchanged',
        re.compile('^objects/[0-9a-f]{2}$'): 'store_directory',
        re.compile('^objects/[0-9a-f]{2}/[0-9a-f]{38}$'): 'store_object_file',
        re.compile('^objects/pack/pack-.*\.pack$'): 'store_packfile_and_index',
    }

    def __init__(self, base_repo_path=None, blob_store=None):
        super(RepoReader, self).__init__(store=blob_store)
        self.base = base_repo_path
        self.expected_files = dict()
        self.unexpected_files = dict()
        self.all_files = dict()
        for rel_path, sha1 in self.EXPECTED_STATIC_FILES.items():
            self._expect_file(rel_path, sha1)

        self.output = {}

    def parse(self):
        unexpected = []
        for root, dirs, files in os.walk(self.base):
            for name in files:
                abs_path = os.path.join(root, name)
                self._parse_file(abs_path, is_dir=False)

            for name in dirs:
                abs_path = os.path.join(root, name)
                self._parse_file(abs_path, is_dir=True)
        self._finalize()

    def _parse_file(self, abs_path, is_dir):
        rel_path = os.path.relpath(abs_path, self.base)
        if is_dir:
            sha = self.DIRECTORY_SHA
        else:
            sha = sha1_path(abs_path)
        self.all_files[rel_path] = sha
        if rel_path in self.expected_files:
            expected_sha = self.expected_files[rel_path]
            if sha == expected_sha or (isinstance(expected_sha, set) and sha in expected_sha):
                self._found_expected(rel_path, sha, is_dir=(sha==self.DIRECTORY_SHA))
            else:
                raise MismatchHashException(rel_path, sha, expected_sha)
        elif rel_path in self.PARSED_FILES:
            assert not is_dir
            with open(abs_path, 'rb') as f:
                getattr(self, self.PARSED_FILES[rel_path])(rel_path, f)
        else:
            matched = False
            regex_keys = [r for r in self.PARSED_FILES.keys() if isinstance(r, re.Pattern)]
            for r in regex_keys:
                if r.match(rel_path):
                    assert not matched
                    if is_dir:
                        getattr(self, self.PARSED_FILES[r])(rel_path)
                    else:
                        with open(abs_path, 'rb') as f:
                            getattr(self, self.PARSED_FILES[r])(rel_path, f)
                    matched = True
            if not matched:
                self.unexpected_files[rel_path] = sha

    def _finalize(self):
        for f in self.expected_files:
            if isinstance(self.expected_files[f], set) and None in self.expected_files[f]:
                continue
            if f not in self.all_files:
                raise MissingFileException(f, is_directory=(self.expected_files[f] == self.DIRECTORY_SHA))
        for f in self.unexpected_files:
            raise UnexpectedFileException(f, is_directory=(self.unexpected_files[f] == self.DIRECTORY_SHA))

    def get_size(self, blobs=True):
        size = 0
        if blobs:
            lengths = [len(v) for v in self.store.values()]
            size += sum(lengths)
            size += len(pickle.dumps(lengths))
        size += len(pickle.dumps(self.output))
        return size

    def serialize(self, f, only_my_blobs=True):
        if only_my_blobs:
            my_store = {h: self.store[h] for h in self.my_blobs}
            pickle.dump(my_store, f)
        else:
            pickle.dump(self.store)
        pickle.dump(self.output, f)

    def parse_pack(self, f):
        # Read header
        header = f.read(4)
        assert header == b'PACK', "Packfile header is wrong--this is probably not a packfile"
        version, = struct.unpack(">i", f.read(4))
        assert version == 2, "Packfile version is not 2"
        num_objects, = struct.unpack(">i", f.read(4))

        # SHA the file and make sure the check at the end matches
        f.seek(-20,2) # 20 bytes from the end
        self_sha = f.read(20)
        length = f.tell()
        f.seek(0)
        buf = f.read(length-20)
        assert hashlib.sha1(buf).digest() == self_sha, "Packfile self-signature is incorrect"
        f.seek(12)

        # Read the individual objects
        object_reprs = []
        for i in range(num_objects):
            t, size, header_buffer = self.parse_object_header(f)
            if t in (1,2,3,4): # un-deltafied
                pos = f.tell()
                decompressed_buffer, compressed_length = decompress(f)
                assert len(decompressed_buffer) == size, "Size wrong"
                f.seek(pos)
                compressed_buffer = f.read(compressed_length)
                gh = git_hash(t, decompressed_buffer)
                print("Parsed an object:", gh, PRINTABLE_TYPES[t], len(decompressed_buffer), compressed_length+len(header_buffer), pos)
            elif t == 6:
                assert False, "Deltas not yet supported"
            else:
                assert False, "Invalid git object type"
            object_reprs.append(header_buffer + compressed_buffer)
                
        assert f.tell() == length-20, "Stopped reading objects at the wrong point"

        return object_reprs

    @classmethod
    def parse_object_header(cls, f):
        start = f.tell()
        parsed = io.BytesIO()
        c = f.read(1)
        parsed.write(c)
        t = (c[0] >> 4) & 0x7
        assert t in (1,2,3,4,6,7) # Valid packfile object types: 0 and 5 are invalid
        assert t in (1,2,3,4,6), "Ref deltas are not really expected in packfiles on disk"
        size = c[0] & 15
        shift = 4
        # Parsing code copied from unpack_object_header_buffer in packfile.c of git
        while c[0] & 0x80:
            assert shift <= 32, "This is probably not a real header--object size too big"
            c = f.read(1)
            parsed.write(c)
            size += 2**shift * (c[0] & 0x7f)
            shift += 7
        n = f.tell()-start
        buf = parsed.getvalue()
        
        redo = RepoWriter.unparse_object_header(t, size)
        assert RepoWriter.unparse_object_header(t, size) == buf, "parse/unparse object header were not opposites"
        print("One header parsed and reconstructed:", t, size)
        return t, size, buf

    def store_unchanged(self, rel_path, f):
        c = f.read()
        h = self.store_blob(c)
        self.output[rel_path] = ('unstore_unchanged', rel_path, h)

    def store_directory(self, rel_path):
        self.output[rel_path] = ('unstore_directory', rel_path)

    def store_expected_directory(self, rel_path):
        self.output[rel_path] = ('unstore_expected_directory', rel_path)

    def store_expected_file(self, rel_path, sha):
        self.output[rel_path] = ('unstore_expected_file', rel_path, sha)

    def store_generated_index(self, rel_path, f_from):
        rel_from = rel_path[:-4]+'.pack'
        # Use 'git' command to generate index file
        with self.generate_index(f_from) as index_file:
            index_sha = sha1_file(index_file)

        # Mark index file in current input as generated
        self._expect_file(rel_path, index_sha)

        self.output[rel_path] = ('unstore_generated_index', rel_path, rel_from, index_sha)

    def store_object_file(self, rel_path, f):
        self.store_unchanged(rel_path, f)

    def store_packfile_and_index(self, rel_path, f):
        # Store packfile
        objs = self.parse_pack(f)
        h = self.store_bloblist(objs)
        self.store_unchanged(rel_path, f)
        f.seek(0)

        # Store pack index file
        index_path = rel_path[:-5]+'.idx'
        self.store_generated_index(index_path, f)

    def _found_expected(self, rel_path, sha, is_dir):
        if rel_path in self.EXPECTED_STATIC_FILES:
            if is_dir:
                self.store_expected_directory(rel_path)
            else:
                self.store_expected_file(rel_path, sha)

    def _expect_file(self, rel_path, expected_sha):
        self.expected_files[rel_path] = expected_sha
        if rel_path in self.unexpected_files:
            actual_sha = self.unexpected_files[rel_path]
            if actual_sha == expected_sha or (isinstance(expected_sha, set) and actual_sha in expected_sha):
                del self.unexpected_files[rel_path]
                self._found_expected(rel_path, actual_sha, is_dir=(actual_sha==self.DIRECTORY_SHA))
            else:
                raise MismatchHashException(rel_path, actual_sha, expected_sha)



if __name__ == '__main__':
    parsers = {}
    common = {}
    per_repo_combined = 0
    for repo in sys.argv[1:]:
        print("Parsing repo {}".format(repo))
        # Read the repo
        parsers[repo] = RepoReader(repo, blob_store=common)
        parsers[repo].parse()
        expected_sha1 = sha1_directory(repo)
        out = io.BytesIO()
        parsers[repo].serialize(out, only_my_blobs=True)
        out.seek(0)

        # Restore the repo
        ds = RepoWriter.unserialize(out)
        d = tempfile.mkdtemp()
        ds.unparse(d)
        actual_sha1 = sha1_directory(d)
        if expected_sha1 == actual_sha1:
            repo_size = parsers[repo].get_size(blobs=False)
            per_repo_combined += repo_size
            print("Size of repo (no blobs) {}: {:,}".format(repo, repo_size))
        else:
            print("Failure--some mismatch. Temp directory was: {}".format(d))
        subprocess.call(["rm", "-r", "-f", d])
    print("Success--exact reproduction for all repos")
    any_parser = parsers[sys.argv[1]]
    print("Size of combined blobs: {:,}".format(any_parser.get_size() - any_parser.get_size(blobs=False)))
    print("Size of combined repos (no blobs): {:,}".format(per_repo_combined))
