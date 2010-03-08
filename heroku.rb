git :init

gems = {
  "haml" => "2.2.9",
  "will_paginate" => "1.4.0",
  "hoptoad_notifier" => "2.1.1",
  "less" => "1.2.21"
}

test_gems = ["factory_girl", "faker", "rspec", "rspec-rails"]

file ".gems", gems.collect { |gem, version| "#{gem} --version \">= #{version}\"" }.join("\n")

hoptoad_api_key = ask("What is the hoptoad API key for your project?")
hoptoad_api_key = hoptoad_api_key.blank? ? "your_api_key_here" : hoptoad_api_key
generate :hoptoad, "--api-key hoptoad_api_key"

#Remove unecessary files
run "rm public/index.html"
run "rm public/favicon.ico"
run "rm public/robots.txt"
run "rm -f public/javascripts/*"

plugin 'jrails', :git => 'git://github.com/aaronchi/jrails.git'

generate :rspec

file 'spec/spec_helper.rb', <<-SPEC_HELPER
ENV["RAILS_ENV"] ||= 'test'
require File.expand_path(File.join(File.dirname(__FILE__),'..','config','environment'))
require 'spec/autorun'
require 'spec/rails'
require 'pp'
require 'factory_girl'

Dir['spec/factories/**/*.rb'].each do |factory|
  require factory
end

# Uncomment the next line to use webrat's matchers
#require 'webrat/integrations/rspec-rails'

# Requires supporting files with custom matchers and macros, etc,
# in ./support/ and its subdirectories.
Dir[File.expand_path(File.join(File.dirname(__FILE__),'support','**','*.rb'))].each {|f| require f}

Spec::Runner.configure do |config|
  # If you're not using ActiveRecord you should remove these
  # lines, delete config/database.yml and disable :active_record
  # in your config/boot.rb
  # config.use_transactional_fixtures = true
  # config.use_instantiated_fixtures  = false
  # config.fixture_path = RAILS_ROOT + '/spec/fixtures/'
  # config.global_fixtures = :all
end

# This is here to allow you to integrate views on all of your controller specs
Spec::Runner.configuration.before(:all, :behaviour_type => :controller) do
  @integrate_views = true
end

class Spec::Rails::Example::ControllerExampleGroup
  extend ResourceControllerHelper::ClassMethods
  include ResourceControllerHelper::InstanceMethods
end

SPEC_HELPER

file ".gitignore", <<-GITIGNORE
log/*
tmp/*
.DS_Store
bin/*
nbproject/*
db/*.sqlite3
GITIGNORE

plugin 'ssl_requirement', :git => 'git://github.com/rails/ssl_requirement.git', :submodule => true
plugin 'gravatar', :git => 'git://github.com/mdeering/gravatar_image_tag.git', :submodule => true

file "lib/email_address.rb", <<-EMAIL
EmailAddress = begin
  qtext = '[^\\x0d\\x22\\x5c\\x80-\\xff]'
  dtext = '[^\\x0d\\x5b-\\x5d\\x80-\\xff]'
  atom = '[^\\x00-\\x20\\x22\\x28\\x29\\x2c\\x2e\\x3a-' +
    '\\x3c\\x3e\\x40\\x5b-\\x5d\\x7f-\\xff]+'
  quoted_pair = '\\x5c[\\x00-\\x7f]'
  domain_literal = "\\x5b(?:\#{dtext}|\#{quoted_pair})*\\x5d"
  quoted_string = "\\x22(?:\#{qtext}|\#{quoted_pair})*\\x22"
  domain_ref = atom
  sub_domain = "(?:\#{domain_ref}|\#{domain_literal})"
  word = "(?:\#{atom}|\#{quoted_string})"
  domain = "\#{sub_domain}(?:\\x2e\#{sub_domain})*"
  local_part = "\#{word}(?:\\x2e\#{word})*"
  addr_spec = "\#{local_part}\\x40\#{domain}"
  pattern = /\A\#{addr_spec}\z/
end
EMAIL
 
inside("spec") do
  run "mkdir support"
end
  
file "spec/support/resource_controller_helper.rb", <<-RESOURCE_CONTROLLER_HELPER
module ResourceControllerHelper
  module InstanceMethods
    def controller_name
      controller.class.to_s.underscore.gsub(/_controller$/, '')
    end

    def request_proc(&block)
      if block_given?
        @request_proc = block
      else
        @request_proc
      end
    end
  end

  module ClassMethods
    def it_has_route(http_method, path, routing_options)
      it "should route \#{http_method.to_s.upcase} \#{path} to \#{routing_options.inspect}" do
        http(http_method, path).should send_request_to({:controller => controller_name}.merge(routing_options))
      end
    end

    def it_should_assign(*instance_variables)
      instance_variables.each do |variable|
        it "should assign \#{variable}" do
          request_proc.call
          assigns(variable).should_not be_nil
        end
      end
    end
  end
end
RESOURCE_CONTROLLER_HELPER
    
file "spec/support/routing_matcher.rb", <<-ROUTING_MATCHER
class RouteTo
  def initialize(routing_hash)
    @expected_route = routing_hash
  end

  def matches?(target)
    @target = target
    ActionController::Routing::Routes.recognize_path(@target.url, :method => @target.method).should == @expected_route
  end

  def failure_message
    "expected \#{@target.inspect} to route to \#{@expected_route.inspect}"
  end

  def negative_failure_message
    "expected \#{@target.inspect} not to route to \#{@expected_route.inspect}"    
  end
end

class RoutingRequest
  attr_accessor :method, :url

  def initialize(method, url)
    @method = method
    @url = url
  end
end

def http(method, url)
  RoutingRequest.new(method, url)
end

def send_request_to(expected)
  RouteTo.new(expected)
end
ROUTING_MATCHER
  
git :add => "."
git :add => "./vendor/gems/ruby/1.8/cache/*"
git :commit => "-a -m 'Initial commit'"
