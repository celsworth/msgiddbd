#!/usr/local/bin/ruby

require 'mkmf'
extension_name = 'murmurhash2'

dir_config(extension_name)

create_makefile(extension_name)

