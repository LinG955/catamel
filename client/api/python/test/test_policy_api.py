# coding: utf-8

"""
    dacat-api

    No description provided (generated by Swagger Codegen https://github.com/swagger-api/swagger-codegen)

    OpenAPI spec version: 2.5.0
    
    Generated by: https://github.com/swagger-api/swagger-codegen.git
"""


from __future__ import absolute_import

import os
import sys
import unittest

import swagger_client
from swagger_client.rest import ApiException
from swagger_client.apis.policy_api import PolicyApi


class TestPolicyApi(unittest.TestCase):
    """ PolicyApi unit test stubs """

    def setUp(self):
        self.api = swagger_client.apis.policy_api.PolicyApi()

    def tearDown(self):
        pass

    def test_policy_count(self):
        """
        Test case for policy_count

        Count instances of the model matched by where from the data source.
        """
        pass

    def test_policy_create(self):
        """
        Test case for policy_create

        Create a new instance of the model and persist it into the data source.
        """
        pass

    def test_policy_create_change_stream_get_policies_change_stream(self):
        """
        Test case for policy_create_change_stream_get_policies_change_stream

        Create a change stream.
        """
        pass

    def test_policy_create_change_stream_post_policies_change_stream(self):
        """
        Test case for policy_create_change_stream_post_policies_change_stream

        Create a change stream.
        """
        pass

    def test_policy_delete_by_id(self):
        """
        Test case for policy_delete_by_id

        Delete a model instance by {{id}} from the data source.
        """
        pass

    def test_policy_exists_get_policiesid_exists(self):
        """
        Test case for policy_exists_get_policiesid_exists

        Check whether a model instance exists in the data source.
        """
        pass

    def test_policy_exists_head_policiesid(self):
        """
        Test case for policy_exists_head_policiesid

        Check whether a model instance exists in the data source.
        """
        pass

    def test_policy_find(self):
        """
        Test case for policy_find

        Find all instances of the model matched by filter from the data source.
        """
        pass

    def test_policy_find_by_id(self):
        """
        Test case for policy_find_by_id

        Find a model instance by {{id}} from the data source.
        """
        pass

    def test_policy_find_one(self):
        """
        Test case for policy_find_one

        Find first instance of the model matched by filter from the data source.
        """
        pass

    def test_policy_patch_or_create(self):
        """
        Test case for policy_patch_or_create

        Patch an existing model instance or insert a new one into the data source.
        """
        pass

    def test_policy_prototype_patch_attributes(self):
        """
        Test case for policy_prototype_patch_attributes

        Patch attributes for a model instance and persist it into the data source.
        """
        pass

    def test_policy_replace_by_id_post_policiesid_replace(self):
        """
        Test case for policy_replace_by_id_post_policiesid_replace

        Replace attributes for a model instance and persist it into the data source.
        """
        pass

    def test_policy_replace_by_id_put_policiesid(self):
        """
        Test case for policy_replace_by_id_put_policiesid

        Replace attributes for a model instance and persist it into the data source.
        """
        pass

    def test_policy_replace_or_create_post_policies_replace_or_create(self):
        """
        Test case for policy_replace_or_create_post_policies_replace_or_create

        Replace an existing model instance or insert a new one into the data source.
        """
        pass

    def test_policy_replace_or_create_put_policies(self):
        """
        Test case for policy_replace_or_create_put_policies

        Replace an existing model instance or insert a new one into the data source.
        """
        pass

    def test_policy_update_all(self):
        """
        Test case for policy_update_all

        Update instances of the model matched by {{where}} from the data source.
        """
        pass

    def test_policy_upsert_with_where(self):
        """
        Test case for policy_upsert_with_where

        Update an existing model instance or insert a new one into the data source based on the where criteria.
        """
        pass


if __name__ == '__main__':
    unittest.main()
