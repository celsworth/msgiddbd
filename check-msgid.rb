#!/usr/local/bin/ruby

require 'socket'
require 'pp'

require 'rubygems'
require 'hpricot'
require 'dbi'

$segdiff = ARGV.delete('diff')
if ARGV.first and ARGV.first =~ /(\d+)\s*-\s*(\d+)/
	file_ids = Range.new($1.to_i, $2.to_i).to_a
else
	file_ids = ARGV.map(&:to_i).reject {|x| x == 0 }
end
exit 42 if file_ids.empty?

SegmentDelimiter = "\n.\n"

DB = DBI.connect("DBI:Mysql:newzDog:db0-mgt", "newzDog", "$h1tePwd")
S = TCPSocket.new('dev1', 15002)
S.sync = true
intro = S.gets
if intro !~ /^200 /
	puts "Not a msgiddbd server?"
	puts intro
	exit
end

Segment = Struct.new(:number, :bytes, :msgid)
class Segment
#	def ==(other)
#		Segment === other and self.number == other.number
#	end
end

def sort_segs(seglist)
	seglist.sort_by {|a| "%.05d %s" % [a.number, a.msgid] }
end

def mysql_tables_for_files(fileids)
	stmt = DB.execute("SELECT tablename from MessageID_Ranges WHERE
	min_fileid <= ? AND max_fileid >= ?", fileids.max, fileids.min)
	tables = []
	while s = stmt.fetch_hash
		tables << s['tablename']
	end
	stmt.finish
	tables
end

def mysql_segs(file_ids)
	files = Hash.new {|h,k| h[k] = [] }
        tables = mysql_tables_for_files(file_ids)
	ids = file_ids.join(",")
	sql = tables.map {|table| "(SELECT * FROM #{table} WHERE mid_fileid IN (#{ids}))" }.join(" UNION ")
	DB.select_all(sql) do |row|
		files[row['mid_fileid'].to_i] << Segment.new(row['mid_segment'].to_i,row['mid_bytes'].to_i,row['mid_msgid'])
	end
	mf = {}
	files.each {|k,v| mf[k] = sort_segs(v) }
	mf
end

log = File.new('msgid-check.log', 'a')
def log.out(msg)
	self.puts("#{Time.new.strftime('%F %T')}: #{msg}")
	STDOUT.puts("\n#{msg}")
end
log.out("Start: #{ARGV.inspect}")

STDOUT.sync = true
start = Time.new
i = 0
total = 0
file_ids.each_slice(25) do |ids|
	#puts "#{ids.first} - #{ids.last}" if i % 50 == 0
	print "\r#{ids.first} - #{ids.last} (#{(total / (Time.new - start)).to_i}/sec)"
	i += 1
	total += ids.size
	my_segs = mysql_segs(ids)
	out = "GET #{ids.join(' ')}\n"
	#print ">> #{out}"
	S.write(out)
	ids.each do |id|
		res = S.gets
		#puts "<< #{res}"
		if res =~ /^205 FILEID (\d+)/
			if $1.to_i != id
				log.out("FileID mismatch in GET, got #{$1}, expected #{id}")
				exit
			end

			segs = []
			buf = S.gets(SegmentDelimiter).chomp(SegmentDelimiter)
			#puts buf
			sd = Hpricot("<segments>#{buf}</segments>")
			#p sd
			(sd / "segments/segment").each do |seg|
				segs << Segment.new(seg.attributes['number'].to_i, seg.attributes['bytes'].to_i, seg.inner_text)
			end
			segs = sort_segs(segs)
			if segs != my_segs[id]
				log.out("Mismatch: #{id}")
				if $segdiff
					File.open('/tmp/segs-msgiddbd', 'w') {|f| f.write(segs.map(&:inspect).join("\n")+"\n") }
					File.open('/tmp/segs-mysql', 'w') {|f| f.write(my_segs[id].map(&:inspect).join("\n")+"\n") }
					system "diff -u /tmp/segs-msgiddbd /tmp/segs-mysql"
				end
			#	puts "Mismatch, MySQL:"
			#	pp my_segs
			#	puts "msgidbdbd:"
			#	pp segs
			else
				#puts "File #{id} matches MySQL"
			end
		else
			log.out("Missing: #{id} (#{res.chomp})")
			#puts "Skipped, != 205"
		end
	end
end
log.close

DB.disconnect
