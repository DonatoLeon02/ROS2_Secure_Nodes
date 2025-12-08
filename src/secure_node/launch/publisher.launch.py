import os
from launch import LaunchDescription
from launch_ros.actions import Node


def generate_launch_description():
    return LaunchDescription([
        Node(
            package='secure_node',
            executable='publisher_node',
            name='secure_publisher',
            output='screen',
        ),
    ])
