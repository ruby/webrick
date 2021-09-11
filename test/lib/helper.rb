require "test/unit"
require_relative "core_assertions"

Test::Unit::TestCase.include Test::Unit::CoreAssertions

module TestWEBrick
  include Test::Unit::Util::Output
  extend Test::Unit::Util::Output
end
