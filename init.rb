require 'redmine'
require 'redmine_openid_connect/application_controller_patch'
require 'redmine_openid_connect/account_controller_patch'
require 'redmine_openid_connect/hooks'

Redmine::Plugin.register :redmine_openid_connect do
  name 'Redmine Openid Connect plugin'
  author 'Alfonso Juan Dillera / Markus M. May'
  description 'OpenID Connect implementation for Redmine'
  version '0.9.3'
  url 'https://github.com/devopskube/redmine_git_remote'
  author_url 'http://github.com/adillera'

  settings :default => { 'empty' => true }, partial: 'settings/redmine_openid_connect_settings'
end

Rails.configuration.to_prepare do
  ApplicationController.send(:prepend, RedmineOpenidConnect::ApplicationControllerPatch)
  AccountController.send(:prepend, RedmineOpenidConnect::AccountControllerPatch)
end
