import os
from launch import LaunchDescription
from launch_ros.actions import Node


def generate_launch_description():
    share_dir = os.path.join(os.getenv('AMENT_PREFIX_PATH', '/opt/ros/humble'), 'share', 'secure_node')
    return LaunchDescription([
        Node(
            package='secure_node',
            executable='publisher_node',
            name='secure_publisher',
            output='screen',
        ),
        Node(
            package='secure_node',
            executable='subscriber_node',
            name='secure_subscriber',
            output='screen',
        ),
    ])
