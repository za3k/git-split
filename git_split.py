#!/bin/python3
import glob
import hashlib
import io
import os
import pickle
import re
import subprocess
import sys
import tempfile

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
    return hasher.hexdigest()
def sha1_directory(d):
    return subprocess.getoutput("find {} -type f | sort | xargs sha1sum | cut -f1 -d' ' | sha1sum | cut -f1 -d' '".format(d))

def copy_write(fr, to):
    BLOCKSIZE=65536
    buf = fr.read(BLOCKSIZE)
    while len(buf) > 0:
        to.write(buf)
        buf = fr.read(BLOCKSIZE)

class MismatchHashException(Exception):
    def __init__(self, rel_path, actual_sha, expected_sha):
        super(MismatchHashException, self).__init__("Unexpected hash {} for file {}, expected {}".format(sha, rel_path, expected_sha))

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
        'description': '9635f1b7e12c045212819dd934d809ef07efa2f4',
        'hooks/applypatch-msg.sample': '4de88eb95a5e93fd27e78b5fb3b5231a8d8917dd',
        'hooks/commit-msg.sample': 'ee1ed5aad98a435f2020b6de35c173b75d9affac',
        'hooks/fsmonitor-watchman.sample': 'f7c0aa40cb0d620ff0bca3efe3521ec79e5d7156',
        'hooks/post-update.sample': 'b614c2f63da7dca9f1db2e7ade61ef30448fc96c',
        'hooks/pre-applypatch.sample': 'f208287c1a92525de9f5462e905a9d31de1e2d75',
        'hooks/pre-commit.sample': '33729ad4ce51acda35094e581e4088f3167a0af8',
        'hooks/prepare-commit-msg.sample': '2584806ba147152ae005cb675aa4f01d5d068456',
        'hooks/pre-push.sample': '5c8518bfd1d1d3d2c1a7194994c0a16d8a313a41',
        'hooks/pre-rebase.sample': '288efdc0027db4cfd8b7c47c4aeddba09b6ded12',
        'hooks/pre-receive.sample': '705a17d259e7896f0082fe2e9f2c0c3b127be5ac',
        'hooks/update.sample': 'e729cd61b27c128951d139de8e7c63d1a3758dde',
        'info/exclude': 'c879df015d97615050afa7b9641e3352a1e701ac',
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
            subprocess.call(["git", "index-pack", pack_path], stdout=FNULL)
        os.remove(pack_path)
        index_file = open(index_path, 'rb')
        os.remove(index_path)
        return index_file

    def store_blob(self, b):
        h = hashlib.sha1(b).hexdigest()
        if h in self.store:
            assert self.store[h] == b, "Two distinct blobs stored with the same hash (collision): {}".format(h)
        else:
            self.store[h] = b
        self.my_blobs.add(h)
        return h

    def load_blob(self, h):
        b = self.store[h]
        assert h in self.my_blobs
        return b


class RepoWriter(RepoBase):
    def __init__(self, store=None):
        super(RepoWriter, self).__init__(store=store)
        self.expected_blobs = {}
        self.my_blobs = set()

        for path in glob.glob('expected/*'):
            with open(path, 'rb') as f:
                b = f.read()
                h = hashlib.sha1(b).hexdigest()
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
            if sha == expected_sha:
                self._found_expected(rel_path, is_dir=(expected_sha==self.DIRECTORY_SHA))
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
            if f not in self.all_files:
                raise MissingFileException(f, is_directory=(self.expected_files[f] == self.DIRECTORY_SHA))
        for f in self.unexpected_files:
            raise UnexpectedFileException(f, is_directory=(self.unexpected_files[f] == self.DIRECTORY_SHA))

    def get_size(self, blobs=True):
        size = 0
        if blobs:
            for h,v in self.store.items():
                size += len(v)
        size += len(pickle.dumps(self.output))
        return size

    def serialize(self, f, only_my_blobs=True):
        if only_my_blobs:
            my_store = {h: self.store[h] for h in self.my_blobs}
            pickle.dump(my_store, f)
        else:
            pickle.dump(self.store)
        pickle.dump(self.output, f)

    def store_unchanged(self, rel_path, f):
        c = f.read()
        h = self.store_blob(c)
        self.output[rel_path] = ('unstore_unchanged', rel_path, h)

    def store_directory(self, rel_path):
        self.output[rel_path] = ('unstore_directory', rel_path)

    def store_expected_directory(self, rel_path):
        self.output[rel_path] = ('unstore_expected_directory', rel_path)

    def store_expected_file(self, rel_path):
        self.output[rel_path] = ('unstore_expected_file', rel_path, self.expected_files[rel_path])

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
        self.store_unchanged(rel_path, f)
        f.seek(0)

        # Store pack index file
        index_path = rel_path[:-5]+'.idx'
        self.store_generated_index(index_path, f)

    def _found_expected(self, rel_path, is_dir):
        if rel_path in self.EXPECTED_STATIC_FILES:
            if is_dir:
                self.store_expected_directory(rel_path)
            else:
                self.store_expected_file(rel_path)

    def _expect_file(self, rel_path, expected_sha):
        self.expected_files[rel_path] = expected_sha
        if rel_path in self.unexpected_files:
            actual_sha = self.unexpected_files[rel_path]
            if actual_sha == expected_sha:
                self._found_expected(rel_path, is_dir=(expected_sha==self.DIRECTORY_SHA))
            else:
                raise MismatchHashException(rel_path, actual_sha, expected_sha)



if __name__ == '__main__':
    parsers = {}
    common = {}
    per_repo_combined = 0
    for repo in sys.argv[1:]:
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
