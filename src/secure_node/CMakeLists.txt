cmake_minimum_required(VERSION 3.5)
project(secure_node)

find_package(ament_cmake REQUIRED)
find_package(rclcpp REQUIRED)
find_package(custom_msgs REQUIRED)
find_package(OpenSSL REQUIRED)

add_executable(publisher_node src/publisher_node.cpp)
ament_target_dependencies(publisher_node rclcpp custom_msgs)
target_include_directories(publisher_node PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(publisher_node OpenSSL::Crypto OpenSSL::SSL)

add_executable(subscriber_node src/subscriber_node.cpp)
ament_target_dependencies(subscriber_node rclcpp custom_msgs)
target_include_directories(subscriber_node PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(subscriber_node OpenSSL::Crypto OpenSSL::SSL)

install(TARGETS
  publisher_node
  subscriber_node
  DESTINATION lib/${PROJECT_NAME}
)

install(DIRECTORY launch
  DESTINATION share/${PROJECT_NAME}
)

ament_package()
