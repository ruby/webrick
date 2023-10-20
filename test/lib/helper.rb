require "test/unit"
require "core_assertions"

Test::Unit::TestCase.include Test::Unit::CoreAssertions

module TestWEBrick
  include Test::Unit::Util::Output
  extend Test::Unit::Util::Output
end
