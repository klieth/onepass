# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'OnePass/version'

Gem::Specification.new do |spec|
  spec.name          = "onepass"
  spec.version       = OnePass::VERSION
  spec.authors       = ["Kai Lieth"]
  spec.email         = ["kai@squareup.com"]
  spec.summary       = %q{Decrypt the secrets stored in 1Password 4}
  spec.description   = %q{A gem that decrypts the secrets that are stored in the 1Password 4 native SQLite database.}
  spec.homepage      = ""
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_dependency "sqlite3", "~> 1.3.9"

  spec.add_development_dependency "bundler", "~> 1.7"
  spec.add_development_dependency "rake", "~> 10.0"
end
