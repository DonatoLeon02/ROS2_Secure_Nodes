import os
from launch import LaunchDescription
from launch_ros.actions import Node


def generate_launch_description():
    return LaunchDescription([
        Node(
            package='secure_node',
            executable='subscriber_node',
            name='secure_subscriber',
            output='screen',
        ),
    ])
