#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# © 2025 The Arizona Board of Regents on behalf of The University of Arizona.
# For license information, see https://cyverse.org/license.

"""Tests of cve.re rule logic."""

from os import path
from pathlib import Path
import subprocess
from subprocess import PIPE
import tarfile
import tempfile
from tempfile import NamedTemporaryFile
import unittest

import test_rules
from test_rules import IrodsTestCase, IrodsType, IrodsVal

from irods.access import iRODSAccess
from irods.api_number import api_number
from irods.data_object import iRODSDataObject
from irods.exception import (
    CAT_NO_ACCESS_PERMISSION, CATALOG_ALREADY_HAS_ITEM_BY_THAT_NAME, CUT_ACTION_PROCESSED_ERR,
    SYS_NOT_ALLOWED)
from irods.message import (
    iRODSMessage, IntegerProperty, LongProperty, Message, RodsHostAddress, StringProperty,
    SubmessageProperty)
from irods.session import iRODSSession
from paramiko import AutoAddPolicy, SSHClient


_TEST_DATA = "/testing/home/rods/test_data"
_TAR_OBJ = "/testing/home/rods/test_data.tar"
_MNT_COLL = "/testing/home/rods/mnt"


def setUpModule():  # pylint: disable=invalid-name
    """Set up main module"""
    test_rules.setUpModule()


def tearDownModule():  # pylint: disable=invalid-name
    """Tear down main module"""
    test_rules.tearDownModule()


class _CveTest(IrodsTestCase):

    def ensure_test_data_exists(self) -> iRODSDataObject:
        """Ensure that the test data object exists"""
        try:
            return self.irods.data_objects.create(_TEST_DATA)
        except CATALOG_ALREADY_HAS_ITEM_BY_THAT_NAME:
            return self.irods.data_objects.get(_TEST_DATA)


class _TarTest(_CveTest):
    """Base class for tests that need a tar file mounted as a collection"""

    def __init__(self, method: str):
        super().__init__(method)
        self._tar_file = Path(tempfile.gettempdir()) / '_TarTest.tar'

    def tearDown(self):
        self.ensure_obj_absent(_TAR_OBJ)
        super().tearDown()

    def mk_safe_tar(self) -> str:
        """Create a tar file containing a single, harmless file and upload it to iRODS"""
        file = NamedTemporaryFile(delete=False)
        file.close()
        with tarfile.open(self._tar_file, "w") as tar:
            tar.add(file.name)
        self.irods.data_objects.put(self._tar_file, _TAR_OBJ)
        self._tar_file.unlink()
        return _TAR_OBJ


class MsitarfileextractTest(_TarTest):
    """Test the rule msiTarFileExtract"""

    @classmethod
    def setUpClass(cls):
        test_rules.clear_rods_log()

    def __init__(self, method: str):
        super().__init__(method)
        self._rc = None

    def setUp(self):
        super().setUp()
        obj_path = self.mk_safe_tar()
        rule = f"""
            *ec = errorcode(msiTarFileExtract('{obj_path}', '', '', *_));
            writeLine('stdout', '*ec');
        """
        self._rc = self.exec_rule(self.mk_rule(rule), IrodsType.INTEGER)

    def test_fail(self):
        """Verify that the microservice failed"""
        self.assertEqual(self._rc, IrodsVal.integer(-169000))

    def test_log_msg(self):
        """Verify that a message was logged"""
        msg = f'msiTarFileExtract: prevented {self.irods.username}#{self.irods.zone}' \
            f' from extracting {_TAR_OBJ}'
        for line in self.tail_rods_log():
            if msg in line:
                return
        self.fail("Didn't log correct message")


class _SpecCollMsg(Message):

    _name = "SpecColl_PI"

    collClass = IntegerProperty()
    type = IntegerProperty()
    collection = StringProperty()
    objPath = StringProperty()
    resource = StringProperty()
    rescHier = StringProperty()
    phyPath = StringProperty()
    cacheDir = StringProperty()
    cacheDirty = IntegerProperty()
    replNum = IntegerProperty()


class _SubFile(Message):

    _name = "SubFile_PI"

    addr = SubmessageProperty(RodsHostAddress)
    subFilePath = StringProperty()
    mode = IntegerProperty()
    flags = IntegerProperty()
    offset = LongProperty()
    specColl = SubmessageProperty(_SpecCollMsg)


class TestPepApiSubStructFilePut(_TarTest):
    """
    Test pep_api_sub_struct_file_put_pre, which blocks writing a subfile into a mounted
    collection's underlying storage. This is the "put-slip" hole that lets iput write into
    msiExecCmd_bin.
    """

    @classmethod
    def setUpClass(cls):
        test_rules.clear_rods_log()

    def __init__(self, method: str):
        super().__init__(method)
        self._result = None

    def setUp(self):
        super().setUp()
        tar_obj_path = self.mk_safe_tar()
        tar_repl = self.irods.data_objects.get(tar_obj_path).replicas[0]
        self.irods.collections.create(_MNT_COLL)
        cmd = f"echo '{test_rules.IRODS_PASSWORD}' | imcoll -m tar {tar_obj_path} {_MNT_COLL}"
        subprocess.run(cmd, stdout=PIPE, stderr=PIPE, shell=True, check=True, encoding='utf-8')
        spec_coll = _SpecCollMsg(
            collClass=1,
            type=2,
            collection=_MNT_COLL,
            objPath=tar_obj_path,
            resource=tar_repl.resource_name,
            rescHier=tar_repl.resc_hier,
            phyPath=tar_repl.path,
            cacheDir=tar_repl.path + ".cacheDir0",
            cacheDirty=1,
            replNum=0)
        sub_file = _SubFile(
            addr=RodsHostAddress(hostAddr="", rodsZone="", port=0, dummyInt=0),
            subFilePath=path.join(path.dirname(_MNT_COLL), "outside.txt"),
            mode=33261,
            flags=0,
            offset=0,
            specColl=spec_coll)
        with self.irods.pool.get_connection() as conn:  # type: ignore
            conn.send(  # type: ignore
                iRODSMessage(
                    "RODS_API_REQ",
                    msg=sub_file,
                    int_info=api_number['SUB_STRUCT_FILE_PUT_AN'],
                    bs=b"PAYLOAD"))
            try:
                conn.recv()
            except SYS_NOT_ALLOWED as e:
                self._result = e

    def tearDown(self):
        subprocess.run(
            f"echo '{test_rules.IRODS_PASSWORD}' | imcoll -U {_MNT_COLL}",
            stdout=PIPE, stderr=PIPE, shell=True, check=True, encoding='utf-8')
        self.irods.collections.remove(_MNT_COLL)
        super().tearDown()

    def test_fail(self):
        """Verify that the PEP rejects the subfile write"""
        self.assertIsInstance(self._result, SYS_NOT_ALLOWED)

    def test_log_msg(self):
        """Verify that a message was logged"""
        msg = (
            f"pep_api_sub_struct_file_put_pre: prevented "
            f"[{self.irods.username}#{self.irods.zone}] from putting a subfile"
        )
        for line in self.tail_rods_log():
            if msg in line:
                return
        self.fail("Didn't log correct message")


# NB: This PEP cannot be triggered except through a custom implementation of the
# iRODS protocol. For now, let's skip testing it.
@test_rules.unimplemented
class TestPepApiSubStructFileGet:
    """Tests of pep_api_sub_struct_file_get_pre"""


class PepApiDataObjCopyPreTestP(_CveTest):
    """Test pep_api_data_obj_copy_pre with -p option"""

    @classmethod
    def setUpClass(cls):
        test_rules.clear_rods_log()

    def __init__(self, method: str):
        super().__init__(method)
        self._copy_data_path = "/testing/home/rods/test_data_copy"
        self._icp_exit_status = None

    def setUp(self):
        super().setUp()
        self.ensure_test_data_exists()
        self.ensure_obj_absent(self._copy_data_path)
        self.update_rulebase([('cyverse_core.re', 'mocks/cyverse_core.re')])
        _, _, stderr = self.ssh.exec_command(
            f'sudo --login --user=irods'
            f' icp -p /var/lib/irods/test_data {_TEST_DATA} {self._copy_data_path}')
        self._icp_exit_status = stderr.channel.recv_exit_status()

    def tearDown(self):
        self.update_rulebase([('cyverse_core.re', '../../files/irods/etc/irods/cyverse_core.re')])
        self.ensure_obj_absent(self._copy_data_path)
        self.ensure_obj_absent(_TEST_DATA)
        super().tearDown()

    def test_no_copy(self):
        """Verify that no copy was made"""
        if self.irods.data_objects.exists(self._copy_data_path):
            self.fail("The file was copied when it shouldn't have been")

    def test_copy_failed(self):
        """Verify that a copy command failed"""
        if self._icp_exit_status == 0:
            self.fail("copy succeeded instead of failed")

    def test_cyversecore_not_called(self):
        """Verify that the cyverse_core.re version of the PEP is not called"""
        for line in self.tail_rods_log():
            if 'cyverse_core: pep_api_data_obj_copy_pre' in line:
                self.fail('cyverse_core version called')


class PepApiDataObjCopyPreTestNoP(_CveTest):
    """Test pep_api_data_obj_copy_pre without -p option"""

    @classmethod
    def setUpClass(cls):
        test_rules.clear_rods_log()

    def __init__(self, method: str):
        super().__init__(method)
        self._copy_data_path = "/testing/home/rods/test_data_copy"
        self._icp_exit_status = None

    def setUp(self):
        super().setUp()
        self.ensure_test_data_exists()
        self.ensure_obj_absent(self._copy_data_path)
        self.update_rulebase([('cyverse_core.re', 'mocks/cyverse_core.re')])
        _, _, stderr = self.ssh.exec_command(
            f'sudo --login --user=irods icp {_TEST_DATA} {self._copy_data_path}')
        self._icp_exit_status = stderr.channel.recv_exit_status()

    def tearDown(self):
        self.update_rulebase([('cyverse_core.re', '../../files/irods/etc/irods/cyverse_core.re')])
        self.ensure_obj_absent(_TEST_DATA)
        self.ensure_obj_absent(self._copy_data_path)
        super().tearDown()

    def test_copy_made(self):
        """Verify that a copy was made"""
        if not self.irods.data_objects.exists(self._copy_data_path):
            self.fail("The file wasn't copied")

    def test_copy_succeeded(self):
        """Verify that the copy command succeeded"""
        if self._icp_exit_status != 0:
            self.fail("copy failed")

    def test_cyversecore_called(self):
        """Verify that the cyverse_core.re version of the PEP is called"""
        for line in self.tail_rods_log():
            if 'cyverse_core: pep_api_data_obj_copy_pre' in line:
                return
        self.fail('cyverse_core version not called')


class PepApiDataObjPutPreTestP(_CveTest):
    """Test pep_api_data_obj_put_pre with -p option"""

    @classmethod
    def setUpClass(cls):
        test_rules.clear_rods_log()

    def __init__(self, method: str):
        super().__init__(method)
        self._iput_resp = None

    def setUp(self):
        super().setUp()
        file = NamedTemporaryFile(delete=False)
        file.close()
        self.update_rulebase([('cyverse_core.re', 'mocks/cyverse_core.re')])
        iput = f"""
            echo '{test_rules.IRODS_PASSWORD}' \
                | iput -p /var/lib/irods/tmp_file '{file.name}' '{_TEST_DATA}'
        """
        resp = subprocess.run(
            iput,
            stdout=PIPE,
            stderr=PIPE,
            shell=True,
            check=False,
            encoding='utf-8')
        self._iput_resp = resp.returncode

    def tearDown(self):
        self.update_rulebase([('cyverse_core.re', '../../files/irods/etc/irods/cyverse_core.re')])
        super().tearDown()

    def test_no_upload(self):
        """Verify that no upload happened"""
        if self.irods.data_objects.exists(_TEST_DATA):
            self.fail("The file was uploaded when it shouldn't have been")

    def test_upload_failed(self):
        """Verify that the upload command failed"""
        if self._iput_resp == 0:
            self.fail("upload succeeded instead of failed")

    def test_cyversecore_not_called(self):
        """Verify that the cyverse_core.re version of the PEP is not called"""
        for line in self.tail_rods_log():
            if 'cyverse_core: pep_api_data_obj_put_pre' in line:
                self.fail('cyverse_core version called')


class PepApiDataObjPutPreTestNoP(_CveTest):
    """Test pep_api_data_obj_put_pre without -p option"""

    @classmethod
    def setUpClass(cls):
        test_rules.clear_rods_log()

    def __init__(self, method: str):
        super().__init__(method)
        self._iput_resp = None

    def setUp(self):
        super().setUp()
        self.update_rulebase([('cyverse_core.re', 'mocks/cyverse_core.re')])
        self.put_empty(_TEST_DATA)

    def tearDown(self):
        self.update_rulebase([('cyverse_core.re', '../../files/irods/etc/irods/cyverse_core.re')])
        self.ensure_obj_absent(_TEST_DATA)
        super().tearDown()

    def test_upload_exists(self):
        """Verify that no upload happened"""
        if not self.irods.data_objects.exists(_TEST_DATA):
            self.fail("The file wasn't uploaded")

    def test_upload_succeeded(self):
        """Verify that a upload command succeeded"""
        if not self._iput_resp:
            self.fail("upload failed")

    def test_cyversecore_called(self):
        """Verify that the cyverse_core.re version of the PEP is called"""
        for line in self.tail_rods_log():
            if 'cyverse_core: pep_api_data_obj_put_pre' in line:
                return
        self.fail("cyverse_core version wasn't called")


class TestDelVal(_CveTest):
    """Test _cve_DEL_VAL"""

    def test(self):
        """Verify that that is is the delete value"""
        self.fn_test('_cve_DEL_VAL', [], IrodsVal.integer(1130))


class TestDeleteAllowed(_CveTest):
    """Test _cve_delete_allowed"""

    def __init__(self, method: str):
        super().__init__(method)
        self._deleter_group = 'deleter_group'
        self._deleter_user = 'deleter_user'
        self._group_member = 'group_member'
        self._reader_user = 'reader'

    def setUp(self):
        super().setUp()
        self.irods.groups.create(self._deleter_group)
        self.ensure_user_exists(self._deleter_user)
        self.ensure_user_exists(self._reader_user)
        self.ensure_user_exists(self._group_member)
        self.irods.groups.addmember(self._deleter_group, self._group_member)
        self.ensure_test_data_exists()
        self.irods.acls.set(iRODSAccess('read', _TEST_DATA, self._reader_user))
        self.irods.acls.set(iRODSAccess('delete_object', _TEST_DATA, self._deleter_user))
        self.irods.acls.set(iRODSAccess('delete_object', _TEST_DATA, self._deleter_group))

    def tearDown(self):
        self.ensure_obj_absent(_TEST_DATA)
        self.irods.users.remove(self._group_member)
        self.irods.users.remove(self._reader_user)
        self.irods.users.remove(self._deleter_user)
        self.irods.groups.remove(self._deleter_group)
        super().tearDown()

    def test_group_write(self):
        """
        Verify that a user that belongs to a group with write permission may delete a data object
        """
        self._call_cve_delete_allowed(self._group_member, True)

    def test_user_delete(self):
        """Verify that a user with delete_object permission may delete a data object"""
        self._call_cve_delete_allowed(self._deleter_user, True)

    def test_user_read(self):
        """Verify that a user with read permission is may not delete a data object"""
        self._call_cve_delete_allowed(self._reader_user, False)

    def _call_cve_delete_allowed(self, username, expected_result):
        for p in IrodsTestCase.prep_path(_TEST_DATA):
            with self.subTest(p=p):
                self.fn_test(
                    '_cve_delete_allowed',
                    [IrodsVal.string(username), IrodsVal.string(self.irods.zone), p],
                    IrodsVal.boolean(expected_result))


class TestPepApiDataObjUnlinkPreRead(_CveTest):
    """Test pep_api_data_obj_unlink_pre prevents reader from deleting replica file"""

    @classmethod
    def setUpClass(cls):
        test_rules.clear_rods_log()

    def __init__(self, method: str):
        super().__init__(method)
        self._user = 'tester'
        self._replica_file = None
        self._deleted = None

    def setUp(self):
        super().setUp()
        self.ensure_user_exists(self._user, 'password')
        obj = self.ensure_test_data_exists()
        self._replica_file = obj.replicas[0]
        self.irods.acls.set(iRODSAccess('write', path.dirname(_TEST_DATA), self._user))
        self.irods.acls.set(iRODSAccess('read', _TEST_DATA, self._user))
        self.update_rulebase([('cyverse_core.re', 'mocks/cyverse_core.re')])
        with iRODSSession(
            host=self.irods.host,
            port=self.irods.port,
            zone=self.irods.zone,
            user=self._user,
            password='password',
        ) as user_sess:
            try:
                user_sess.data_objects.unlink(_TEST_DATA, force=True)
                self._deleted = True
            except CAT_NO_ACCESS_PERMISSION:
                self._deleted = False
            except CUT_ACTION_PROCESSED_ERR:
                self._deleted = False

    def tearDown(self):
        self.update_rulebase([('cyverse_core.re', '../../files/irods/etc/irods/cyverse_core.re')])
        self.ensure_obj_absent(_TEST_DATA)
        self.irods.users.remove(self._user)
        super().tearDown()

    def test_command_failed(self):
        """Verify that the command failed"""
        if self._deleted:
            self.fail("The command should have failed")

    def test_replica_file_exists(self):
        """Verify that a replica file is not removed"""
        if self._replica_file:
            resc = self.irods.resources.get(self._replica_file.resource_name)
            ssh = SSHClient()
            ssh.set_missing_host_key_policy(AutoAddPolicy())
            ssh.connect(resc.location, password='')  # pylint: disable=no-member  # type: ignore
            _, stdout, _ = ssh.exec_command(f"test -e '{self._replica_file.path}'")
            if stdout.channel.recv_exit_status() != 0:
                self.fail("replica was deleted")
            ssh.close()

    def test_cyversecore_not_called(self):
        """Verify that the cyverse_core.re version of the PEP is not called"""
        for line in self.tail_rods_log():
            if 'cyverse_core: pep_api_data_obj_unlink_pre' in line:
                self.fail('cyverse_core version called')


class TestPepApiDataObjUnlinkPreDelete(_CveTest):
    """Test pep_api_data_obj_unlink_pre allows deleter to delete replica file"""

    @classmethod
    def setUpClass(cls):
        test_rules.clear_rods_log()

    def __init__(self, method: str):
        super().__init__(method)
        self._user = 'tester'
        self._deleted = None

    def setUp(self):
        super().setUp()
        self.ensure_user_exists(self._user, 'password')
        obj = self.ensure_test_data_exists()
        self._replica_file = obj.replicas[0]
        self.irods.acls.set(iRODSAccess('write', path.dirname(_TEST_DATA), self._user))
        self.irods.acls.set(iRODSAccess('delete_object', _TEST_DATA, self._user))
        self.update_rulebase([('cyverse_core.re', 'mocks/cyverse_core.re')])
        with iRODSSession(
            host=self.irods.host,
            port=self.irods.port,
            zone=self.irods.zone,
            user=self._user,
            password='password',
        ) as user_sess:
            try:
                user_sess.data_objects.unlink(_TEST_DATA, force=True)
                self._deleted = True
            except CAT_NO_ACCESS_PERMISSION:
                self._deleted = False

    def tearDown(self):
        self.update_rulebase([('cyverse_core.re', '../../files/irods/etc/irods/cyverse_core.re')])
        self.ensure_obj_absent(_TEST_DATA)
        self.irods.users.remove(self._user)
        super().tearDown()

    def test_command_succeeded(self):
        """Verify that the command succeeded"""
        if self._deleted is not True:
            self.fail("The command should have succeeded")

    def test_obj_deleted(self):
        """Verify that data object deleted"""
        if self.irods.data_objects.exists(_TEST_DATA):
            self.fail("the data object wasn't deleted")

    def test_cyversecore_called(self):
        """Verify that the cyverse_core.re version of the PEP is called"""
        for line in self.tail_rods_log():
            if 'cyverse_core: pep_api_data_obj_unlink_pre' in line:
                return
        self.fail('cyverse_core version not called')


if __name__ == "__main__":
    unittest.main()
