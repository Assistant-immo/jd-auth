$:.push File.expand_path("../lib", __FILE__)

# Maintain your gem's version:
require "jd_auth/version"

# Describe your gem and declare its dependencies:
Gem::Specification.new do |s|
  s.name        = "jd_auth"
  s.version     = JdAuth::VERSION
  s.authors     = ["Nicolas Marlier"]
  s.email       = ["nicolas@juliedesk.com"]
  s.homepage    = ""
  s.summary     = ""
  s.description = ""
  s.license     = ""

  s.files = Dir["{app,config,db,lib}/**/*", "Rakefile", "README.md"]

  s.add_dependency "rails"
  s.add_dependency "redis"


  s.add_development_dependency 'rspec-rails'
  s.add_development_dependency 'combustion'
  s.add_development_dependency 'simplecov'

  s.test_files = Dir["spec/**/*"]
end
