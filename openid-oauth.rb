run "rm public/index.html"

# Gem dependency install
gem 'rspec', :version => '>= 1.2.6', :lib => 'spec'
gem 'rspec-rails', :version => '>= 1.2.6', :lib => 'spec/rails'
gem 'machinist', :source => 'http://gemcutter.org'
gem 'guid', :version => ">= 0.1.1"
gem "haml", :version => ">= 2.2"
gem 'sqlite3-ruby', :lib => 'sqlite3'
gem 'ruby-openid', :version => ">= 2.1.7", :lib => 'openid'
gem 'authlogic-oid', :version => ">= 1.0.4", :lib => "authlogic_openid"
gem 'authlogic', :version => ">= 2.1.2"
gem "oauth", :version => ">= 0.3.6"
gem "oauth-plugin", :version => ">= 0.3.14"
gem 'will_paginate', :version => '>= 2.3.11', :source => 'http://gemcutter.org'
gem 'aasm'

rake "gems:install", :sudo => true 

# Initialize the git repo so we can use submodules for plugins
git :init

# Install the open id plugin
plugin 'open_id_authentication', :git => 'git://github.com/rails/open_id_authentication.git', :submodule => true
rake "open_id_authentication:db:create"

# Install Authlogic openid consumer scaffold
file "db/migrate/#{DateTime.now.strftime('%Y%m%d%H%M%S')}_create_users.rb", <<-MIGRATION
  class CreateUsers < ActiveRecord::Migration
    def self.up
      create_table :users do |t|
        t.string :email
        t.string :persistence_token
        t.datetime :current_login_at
        t.datetime :last_login_at
        t.string :crypted_password_field
        t.string :password_salt_field
        t.string :openid_identifier
        t.string :full_name
        t.string :first_name
        t.string :last_name
        t.string :country
        t.string :timezone
        t.timestamps
      end
    end

    def self.down
      drop_table :users
    end
  end
MIGRATION

file "app/models/user.rb", <<-USER
class User < ActiveRecord::Base  
  acts_as_authentic do |user|
    user.openid_required_fields = [:email, "http://axschema.org/contact/email"]
    user.openid_optional_fields = [
      :fullname, 
      :country, 
      :timezone, 
      "http://axschema.org/namePerson/last", 
      "http://axschema.org/namePerson/first"
    ]
  end
  
  has_many :client_applications
  has_many :tokens, :class_name=>"OauthToken",:order=>"authorized_at desc",:include=>[:client_application]

  attr_accessor :password, :password_confirmation

  validates_presence_of :openid_identifier

  def to_s
    email
  end

  private

  def map_openid_registration(registration)
    self.email ||= registration["email"] || ax(registration["http://axschema.org/contact/email"])
    self.full_name ||= registration["fullname"]
    self.country ||= registration["country"]
    self.timezone ||= registration["timezone"]
    self.last_name ||= ax(registration["http://axschema.org/namePerson/last"])
    self.first_name ||= ax(registration["http://axschema.org/namePerson/first"])    
  end  

  def ax(attribute)
    attribute && !attribute.empty? ? attribute.first : nil
  end
  end
USER
  
file "app/controllers/application_controller.rb", <<-APP
class ApplicationController < ActionController::Base
  include Authentication::Controller
  helper :all # include all helpers, all the time
  protect_from_forgery # See ActionController::RequestForgeryProtection for details

  filter_parameter_logging :password
end
APP
    
file "app/controllers/user_sessions_controller.rb", <<-USER_SESSIONS
class UserSessionsController < ApplicationController
  skip_before_filter :store_location

  def new
    logout!
    @user_session = UserSession.new
  end

  def create
    @user_session = UserSession.new(params[:user_session])
    @user_session.save do |result|
      if result
        flash[:notice] = "Successfully logged in."
        redirect_back_or_default root_path
      else
        render :action => 'new'
      end
    end
  end

  def destroy
    logout!
    redirect_to root_path
  end
end
USER_SESSIONS
    
file "app/controllers/users_controller.rb", <<-USERS
class UsersController < ApplicationController
  skip_before_filter :store_location, :only => [:new]

  before_filter :login_required, :only => [:update, :edit]
  before_filter :load_user, :only => [:update, :edit]
  before_filter :current_user_must_be_user_resource, :only => [:update, :edit]

  def new
    @user = User.new
  end

  def edit
  end

  def index
    @users = User.all
  end

  def create
    @user = User.new(params[:user])
    @user.save do |result|
      if result
        flash[:notice] = "Registration successful."
        redirect_to post_registration_path
      else
        render :action => 'edit'
      end
    end
  end

  def update
    @user.attributes = params[:user]
    @user.save do |result|
      if result
        flash[:notice] = "Successfully updated profile."
        redirect_to edit_user_path(@user)
      else
        render :action => 'edit'
      end
    end
  end

  private

  def load_user
    @user = User.find(params[:id])
  end

  def current_user_must_be_user_resource
    unless current_user == @user
      access_denied
    end
  end

  def post_registration_path
    root_path
  end
end  
USERS
  
  
file "lib/authentication.rb", <<-AUTH
module Authentication
  module Controller    
    def self.included(base)
      base.class_eval do
        before_filter :store_location
        helper_method :current_user, :logged_in?, :authorized?
      end
    end

    def logged_in?
      !!current_user_session
    end

    def current_user_session
      return @current_user_session if defined?(@current_user_session)
      @current_user_session = UserSession.find
    end

    def current_user
      return @current_user if defined?(@current_user)
      @current_user = current_user_session && current_user_session.user
    end

    def login_required
      authorized? || access_denied
    end

    def authorized?(action = action_name, resource = nil)
      logged_in?
    end

    def access_denied
      respond_to do |format|
        format.html do
          store_location
          redirect_to login_path
        end
      end
    end

    def store_location
       session[:return_to] = request.request_uri
    end

    def redirect_back_or_default(default)
      location = session[:return_to].blank? ? default : session[:return_to]
      session[:return_to] = nil
      redirect_to(location)
    end

    def logout!
      current_user_session.destroy if logged_in?
    end
  end
end
AUTH
  
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
  
inside("views") do
  run "mkdir user_sessions"
  run "mkdir users"
end

file "app/views/user_sessions/new.html.haml", <<-NEW
%h1
  Sign in

= error_messages_for :user_session

- form_for :user_session, :url => login_path do |f|
  %p
    = f.label :openid_identifier
    = f.text_field :openid_identifier
  %p
    = f.submit "Sign In"
NEW
    
file "app/views/users/new.html.haml", <<-NEW
%h1
  Sign up

= error_messages_for :user

- form_for @user do |f|
  %p
    = f.label :openid_identifier
    = f.text_field :openid_identifier
  %p
    = f.submit "Sign Up"
NEW
    
file "app/views/users/index.html.haml", <<-INDEX
%h1
  Users

.flash= flash[:message]

%ul
  - @users.each do |user|
    %li= link_to(user, edit_user_path(user))
INDEX

file "app/views/users/edit.html.haml", <<-EDIT
%h1
  Edit

= error_messages_for :user

- form_for @user do |f|
  %p
    = f.label :openid_identifier
    = f.text_field :openid_identifier
  %p
    = f.label :email
    = f.text_field :email
  %p
    = f.label :first_name
    = f.text_field :first_name
  %p
    = f.label :last_name
    = f.text_field :last_name
  %p
    = f.label :full_name
    = f.text_field :full_name
  %p
    = f.submit "Sign Up"
EDIT

route "map.resources :users"
route "map.login 'login', :controller => 'user_sessions', :action => 'new', :conditions => { :method => :get }"
route "map.create_login 'login', :controller => 'user_sessions', :action => 'create', :conditions => { :method => :post }"
route "map.logout 'logout', :controller => 'user_sessions', :action => 'destroy', :conditions => { :method => :delete }"
route "map.signup 'signup', :controller => 'users', :action => 'new'"

generate :rspec
generate :session, "user_session"
generate :oauth_provider
generate :oauth_consumer

inside("spec") do
  run "mkdir spec_helpers"
end

file "spec/spec_helper.rb", <<-SPEC_HELPER
# This file is copied to ~/spec when you run 'ruby script/generate rspec'
# from the project root directory.
ENV["RAILS_ENV"] ||= 'test'
require File.expand_path(File.join(File.dirname(__FILE__),'..','config','environment'))
require 'spec/autorun'
require 'spec/rails'
require 'pp'
require 'spec_helpers/resource_controller_helper'
require 'spec_helpers/routing_matcher'
require 'authlogic/test_case'

# Uncomment the next line to use webrat's matchers
#require 'webrat/integrations/rspec-rails'

# Requires supporting files with custom matchers and macros, etc,
# in ./support/ and its subdirectories.
Dir[File.expand_path(File.join(File.dirname(__FILE__),'support','**','*.rb'))].each {|f| require f}

Spec::Runner.configure do |config|
  config.use_transactional_fixtures = true
  config.use_instantiated_fixtures  = false
  config.fixture_path = RAILS_ROOT + '/spec/fixtures/'
  config.global_fixtures = :all
end

Spec::Runner.configuration.before(:all, :behaviour_type => :controller) do
  @integrate_views = true
end

class Spec::Rails::Example::ControllerExampleGroup
  extend ResourceControllerHelper::ClassMethods
  include ResourceControllerHelper::InstanceMethods
  setup :activate_authlogic
end
SPEC_HELPER
  
file "spec/spec_helpers/resource_controller_helper.rb", <<-RESOURCE_CONTROLLER_HELPER
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
    
file "spec/spec_helpers/routing_matcher.rb", <<-ROUTING_MATCHER
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
  
file "spec/models/user_spec.rb", <<-USER_SPEC
require 'spec_helper'

describe User do
  before(:each) do
    @user = User.new(
      :email => 'me@example.com',
      :openid_identifier => 'http://id.com'
    )
  end

  it "should be valid" do
    @user.should be_valid
  end

  describe "validations" do
    it "should require an email" do
      @user.email = ""
      @user.should have(2).errors_on(:email)
    end

    it "should require a valid email address" do
      @user.email = "not.an.address"
      @user.should have(1).error_on(:email)
    end

    it "should require that the email address be unique" do
      User.create(:email => 'me@example.com', :openid_identifier => 'http://id.com')
      @user.should have(1).error_on(:email)
    end

    it "should require an openid identifier" do
      @user.openid_identifier = ""
      @user.should have(1).error_on(:openid_identifier)
    end

    it "should require the openid identifier be unique" do
      User.create(:email => 'me@example.com', :openid_identifier => 'http://id.com')
      @user.should have(1).error_on(:openid_identifier)
    end
  end
end

USER_SPEC
  
  
file "spec/controllers/user_sessions_controller_spec.rb", <<-USER_SESSIONS_CONTROLLER
require 'spec_helper'

describe UserSessionsController do
  it_has_route :get, "/login", :controller => 'user_sessions', :action => 'new'
  it_has_route :post, "/login", :controller => 'user_sessions', :action => 'create'
  it_has_route :delete, "/logout", :controller => 'user_sessions', :action => 'destroy'

  describe "#new" do
    it "should succeed" do
      get :new
      response.should be_success
    end
  end

  describe "#create" do
    before(:each) do
      @user_session = UserSession.new(:openid_identifier => "http://example.com/openid")
      request_proc { post :create, :user_session => {:openid_identifier => "http://example.com/openid" }}
      UserSession.stub!(:new).and_return(@user_session)
    end

    context "when open id authentication succeeds" do
      before(:each) do
        @user_session.stub!(:save).and_yield(true)
      end

      it "should set the flash notice" do
        request_proc.call
        flash[:notice].should_not be_blank
      end

      it "should redirect back or to the root_path" do
        request_proc.call
        response.should redirect_to(root_path)
      end
    end

    context "when open id authentication fails" do
      before(:each) do
        @user_session.stub!(:save).and_yield(false)
      end

      it "should render the new template" do
        request_proc.call
        response.should render_template('new')
      end
    end
  end

  describe "#destroy" do
    it "should redirect to root" do
      delete :destroy
      response.should redirect_to(root_path)
    end
  end
end
USER_SESSIONS_CONTROLLER
    
file "spec/controllers/users_controller_spec.rb", <<-USERS_CONTROLLER
require 'spec_helper'

shared_examples_for "login required" do
  context "without a logged in user" do
    before(:each) do
      session = UserSession.find
      session.destroy if session
    end

    it "should be access denied" do
      request_proc.call
      response.should redirect_to(login_path)
    end
  end
end

shared_examples_for "user must be user resource" do
  context "with a logged in user" do
    before(:each) do
      controller.stub!(:current_user).and_return(users(:nosy))
    end

    context "that is the different from the user in the URL" do
      it "should be access denied" do
         request_proc.call
         response.should redirect_to(login_path)
      end
    end
  end
end

describe UsersController do
  it_has_route :get, "/users/new", :controller => 'users', :action => 'new'
  it_has_route :get, "/signup", :controller => 'users', :action => 'new'
  it_has_route :get, "/users/2/edit", :controller => 'users', :action => 'edit', :id => '2'
  it_has_route :post, "/users", :controller => 'users', :action => 'create'
  it_has_route :put, "/users/2", :controller => 'users', :action => 'update', :id => '2'

  describe "#new" do
    before(:each) do
      request_proc { get :new }
    end

    it "should succeed" do
      request_proc.call
    end

    it_should_assign :user
  end

  describe "#edit" do
    before(:each) do
      @user = users(:valid_user)
      request_proc do
        get :edit, :id => @user.to_param
      end
    end

    it_should_behave_like "login required"
    it_should_behave_like "user must be user resource"

    context "with a logged in user that is the same as the user in the URL" do
      before(:each) do
        UserSession.create(@user)
      end

      it "should succeed" do
        request_proc.call
        response.should be_success
      end

      it_should_assign :user
    end
  end

  describe "#create" do
    before(:each) do
      @user = users(:valid_user)
      request_proc { post :create, :openid_identifier => "http://example.com/openid" }
      User.stub!(:new).and_return(@user)
    end

    context "when opendID autentication succeeds" do
      before(:each) do
        @user.stub!(:save).and_yield(true)
      end

      it_should_assign :user

      it "should redirect to the post_registration_path" do
        request_proc.call
        response.should redirect_to(root_path)
      end

      it "should set the flash message" do
        request_proc.call
        flash[:notice].should == "Registration successful."
      end
    end

    context "when opendID autentication fails" do
      before(:each) do
        @user.stub!(:save).and_yield(false)
      end

      it_should_assign :user

      it "should redirect to the edit path" do
        request_proc.call
        response.should render_template('edit')
      end
    end    
  end

  describe "#update" do
    before(:each) do
      @user = users(:valid_user)
      request_proc { put :update, :id => @user.to_param }
      User.stub!(:find).and_return(@user)
    end

    it_should_behave_like "login required"
    it_should_behave_like "user must be user resource"

    context "with a logged in user" do
      before(:each) do
        UserSession.create(@user)
      end

      context "with valid parameters" do
        before(:each) do
          @user.stub!(:save).and_yield(true)
          request_proc { put :update, :id => @user.to_param, :openid_identifier => "http://example.com/openid", :email => 'address@example.com' }
        end

        it_should_assign :user

        it "should set the flash notice" do
          request_proc.call
          flash[:notice].should_not be_blank
        end

        it "should redirect to the edit path" do
          request_proc.call
          response.should redirect_to(edit_user_path(@user))
        end
      end

      context "with invalid parameters" do
        before(:each) do
          @user.stub!(:save).and_yield(false)
          request_proc { put :update, :id => @user.to_param }
        end

        it_should_assign :user

        it "should render the edit template" do
          request_proc.call
          response.should render_template('edit')
        end
      end
    end
  end
end
USERS_CONTROLLER
  
file "spec/fixtures/users.yml", <<-USERS
valid_user:
  email: MyString
  persistence_token: MyString
  current_login_at: 2009-10-13 22:47:28
  last_login_at: 2009-10-13 22:47:28
  openid_identifier: MyString

nosy:
  email: MyString
  persistence_token: MyString
  current_login_at: 2009-10-13 22:47:28
  last_login_at: 2009-10-13 22:47:28
  openid_identifier: MyString
USERS

file '.gitignore', <<-END
.DS_Store
log/*.log
tmp/**/*
config/database.yml
db/*.sqlite3
END

run "rm README"
run "rm public/favicon.ico"
run "rm public/robots.txt"

git :add => "."
git :commit => "-a -m 'Initial commit'"
