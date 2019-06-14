#!/bin/python3
import glob
import hashlib
import io
import os
import pickle
import re
import sys

def sha1_path(path):
    hasher = hashlib.sha1()
    BLOCKSIZE=65536
    with open(path, 'rb') as f:
        buf = f.read(BLOCKSIZE)
        while len(buf) > 0:
            hasher.update(buf)
            buf = f.read(BLOCKSIZE)
    return hasher.hexdigest()

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

DIRECTORY_SHA = "DIRECTORY"
class OUTPUT:
    MAKE_EXPECTED = 1
    CAT = 2
class RepoParse():
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
    PARSED_FILES = {
        'packed-refs': 'store_unchanged',
        'config': 'store_unchanged',
        'HEAD': 'store_unchanged',
        re.compile('objects/pack/pack-.*\.pack'): 'store_unchanged',
        re.compile('objects/pack/pack-.*\.idx'): 'store_unchanged',
    }

    def __init__(self, base_repo_path=None):
        self.base = base_repo_path
        self.expected_files = dict()
        self.unexpected_files = dict()
        self.all_files = dict()
        for rel_path, sha1 in self.EXPECTED_STATIC_FILES.items():
            self.expect_file(rel_path, sha1)

        self.store = {}
        self.output = {}

    def store_blob(self, b):
        h = hashlib.sha1(b).hexdigest()
        self.store[h] = b
        return h

    def store_unchanged(self, rel_path, f):
        c = f.read()
        h = self.store_blob(c)
        self.output[rel_path] = ('cat', h)

    def found_expected(self, rel_path, is_dir):
        if is_dir:
            self.output[rel_path] = ('make_dir', rel_path)
        else:
            self.output[rel_path] = ('cat', self.expected_files[rel_path])

    def expect_file(self, rel_path, expected_sha):
        self.expected_files[rel_path] = expected_sha
        if rel_path in self.unexpected_files:
            actual_sha = self.unexpected_files[rel_path]
            if actual_sha == expected_sha:
                self.found_expected(rel_path, is_dir=(expected_sha==DIRECTORY_SHA))
            else:
                raise MismatchHashException(rel_path, actual_sha, expected_sha)

    def parse_file(self, abs_path, is_dir):
        rel_path = os.path.relpath(abs_path, self.base)
        if is_dir:
            sha = DIRECTORY_SHA
        else:
            sha = sha1_path(abs_path)
        self.all_files[rel_path] = sha
        if rel_path in self.expected_files:
            expected_sha = self.expected_files[rel_path]
            if sha == expected_sha:
                self.found_expected(rel_path, is_dir=(expected_sha==DIRECTORY_SHA))
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
                    assert not is_dir
                    assert not matched
                    with open(abs_path, 'rb') as f:
                        getattr(self, self.PARSED_FILES[r])(rel_path, f)
                    matched = True
            if not matched:
                self.unexpected_files[rel_path] = sha

    def finalize(self):
        for f in self.expected_files:
            if f not in self.all_files:
                raise MissingFileException(f, is_directory=(self.expected_files[f] == DIRECTORY_SHA))
        for f in self.unexpected_files:
            raise UnexpectedFileException(f, is_directory=(self.unexpected_files[f] == DIRECTORY_SHA))

    @classmethod
    def parse(cls, bare_repo_path):
        parser = RepoParse(bare_repo_path)
        unexpected = []
        for root, dirs, files in os.walk(bare_repo_path):
            for name in files:
                abs_path = os.path.join(root, name)
                parser.parse_file(abs_path, is_dir=False)

            for name in dirs:
                abs_path = os.path.join(root, name)
                parser.parse_file(abs_path, is_dir=True)
        parser.finalize()
        return parser

    def serialize(self, f):
        pickle.dump(self.store, f)
        pickle.dump(self.output, f)

    @classmethod
    def unserialize(cls, f):
        parser = RepoParse()
        parser.store = pickle.load(f)
        parser.output = pickle.load(f)
        return parser

    def unparse(self, extract_path):
        self.base = extract_path
        for path in glob.glob('expected/*'):
            with open(path, 'rb') as f:
                c = f.read()
                self.store_blob(c)
        for rel_path, (action, *args) in self.output.items():
            abs_path = os.path.join(extract_path, rel_path)
            if action == 'make_dir':
                os.mkdir(abs_path)
            elif action == 'cat':
                with open(abs_path, 'wb') as f:
                    f.write(self.store[args[0]])
            else:
                raise Exception("Unexpected output action {}".format(action))

if __name__ == '__main__':
    parsed = RepoParse.parse(sys.argv[1])
    out = io.BytesIO()
    parsed.serialize(out)
    out.seek(0)
    ds = RepoParse.unserialize(out)
    ds.unparse("/tmp/test")
