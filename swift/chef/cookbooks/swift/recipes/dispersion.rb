#
# Copyright 2012, Dell
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# Is there a load-balancer in the environment?
env_filter = " AND haproxy_config_environment:haproxy-config-#{node[:swift][:haproxy_instance]}"
proxy_servers= search(:node, "roles:haproxy #{env_filter}")
if proxy_servers.length > 0
  #load-balancer found - get admin vip
  node[:swift][:load_balanced] = true
  Chef::Log.info("Swift:Dispersion - HAProxy server #{proxy_servers[0].name} found at #{proxy_servers[0].ipaddress}")
  haproxy_machine_name = "haproxy-config-#{node[:swift][:haproxy_instance]}.#{proxy_servers[0].domain}"
  
  # get admin network vip
  admin_net_db = data_bag_item('crowbar', 'admin_network')
  admin_keystone_endpoint = admin_net_db["allocated_by_name"]["#{haproxy_machine_name}"]["address"]
  Chef::Log.info("Swift:Dispersion - admin network virtual IP - #{admin_keystone_endpoint}")   
else
  node[:swift][:load_balanced] = false
  Chef::Log.info("Swift:Dispersion - HAProxy server NOT found - using local IP addresses")
end

env_filter = " AND keystone_config_environment:keystone-config-#{node[:swift][:keystone_instance]}"
keystones = search(:node, "recipes:keystone\\:\\:server#{env_filter}") || []
if keystones.length > 0
  keystone = keystones[0]
else
  keystone = node
end

if node[:swift][:load_balanced]
  # if we're in a ha environment then use the load-balancer vip
  keystone_address = admin_keystone_endpoint
else
  keystone_address = Chef::Recipe::Barclamp::Inventory.get_network_by_type(keystone, "admin").address if keystone_address.nil?
end
keystone_token = keystone["keystone"]["service"]["token"] rescue nil
keystone_service_port = keystone["keystone"]["api"]["service_port"] rescue nil
keystone_admin_port = keystone["keystone"]["api"]["admin_port"] rescue nil

service_tenant = node[:swift][:dispersion][:service_tenant]
service_user = node[:swift][:dispersion][:service_user]
service_password = node[:swift][:dispersion][:service_password]
keystone_auth_url = "http://#{keystone_address}:#{keystone_admin_port}/v2.0"

keystone_register "swift dispersion wakeup keystone" do
  host keystone_address
  port keystone_admin_port
  token keystone_token
  action :wakeup
end

keystone_register "create tenant #{service_tenant} for dispersion" do
  host keystone_address
  port keystone_admin_port
  token keystone_token
  tenant_name service_tenant
  action :add_tenant
end

keystone_register "add #{service_user}:#{service_tenant} user" do
  host keystone_address
  port keystone_admin_port
  token keystone_token
  user_name service_user
  user_password service_password
  tenant_name service_tenant 
  action :add_user
end

keystone_register "add #{service_user}:#{service_tenant} user admin role" do
  host keystone_address
  port keystone_admin_port
  token keystone_token
  user_name service_user
  role_name "admin"
  tenant_name service_tenant 
  action :add_access
end

execute "populate-dispersion" do
  command "swift-dispersion-populate"
  user node[:swift][:user]
  action :run
  ignore_failure true
  only_if "swift -V 2.0 -U #{service_tenant}:#{service_user} -K '#{service_password}' -A #{keystone_auth_url} stat dispersion_objects 2>&1 | grep 'Container.*not found'"
end

template "/etc/swift/dispersion.conf" do
  source     "disperse.conf.erb"
  mode       "0600"
  group       node[:swift][:group]
  owner       node[:swift][:user]
  variables(
    :auth_url => keystone_auth_url
  )
  #only_if "swift-recon --md5 | grep -q '0 error'"
  #notifies :run, "execute[populate-dispersion]", :immediately
end
