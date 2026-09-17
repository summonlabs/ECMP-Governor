#include "test_framework.hpp"

int main(int argc, char** argv) {
  return ecmp::test::run_all(argc > 0 ? argv[0] : "ecmp_tests");
}
