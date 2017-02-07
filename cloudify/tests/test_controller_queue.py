import os
import testtools

from cloudify.test_utils import workflow_test


class ControllertTests(testtools.TestCase):

    test_blueprint_path = os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        "resources/blueprints/test-controller-queue.yaml")

    @workflow_test(blueprint_path=test_blueprint_path,
                   resources_to_copy=[
                       'resources/blueprints/execute_operation_workflow.yaml'])
    def test_controller_queue_property(self, cfy_local):
        cfy_local.execute('install')

        instance = cfy_local.storage.get_node_instances('direct')[0]
        self.assertEqual(
            instance.properties['controller_queue'], 'direct')
        instance = cfy_local.storage.get_node_instances('host_none')[0]
        self.assertEqual(instance.properties['controller,queue'], '')
        instance = cfy_local.storage.get_node_instances(
            'connected_host')[0]
        self.assertEqual(
            instance.properties['controller_queue'], 'queue')
        instance = cfy_local.storage.get_node_instances(
            'direct_override')[0]
        self.assertEqual(
            instance.properties['controller_queue'], 'direct_override')
        instance = cfy_local.storage.get_node_instances(
            'contained_node')[0]
        self.assertEqual(
            instance.properties['controller_queue'], 'father_host')