cmake_minimum_required(VERSION 3.5)
project(custom_msgs)

find_package(ament_cmake REQUIRED)
find_package(rosidl_default_generators REQUIRED)

rosidl_generate_interfaces(${PROJECT_NAME}
  "msg/Handshake.msg"
  "msg/SignedData.msg"
  "srv/Handshake.srv"
  SKIP_GROUP_MEMBERSHIP_CHECK
)

ament_export_dependencies(rosidl_default_runtime)
ament_package()
