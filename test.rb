#!/usr/local/bin/ruby

require 'pp'

check_db = false
if check_db
	require 'dbi'
	DB = DBI.connect("DBI:Mysql:newzDog:db5", 'newzDog', '$h1tePwd')
end

Segment = Struct.new(:date, :size, :segment, :msgid_len, :msgid)
Segments = Struct.new(:next_segments, :segment_magic, :segment_count, :segments)

FileID = Struct.new(:fileid, :size_used, :page_alloc, :first_segments, :cur_segments)

FDatHeader = Struct.new(:file_magic, :file_version, :fileid_min, :fileid_max, :fileid_min_req, :fileid_max_req, :files_used, :files_allocated)
SDatHeader = Struct.new(:file_magic, :file_version, :first_segment, :next_free_segment)

module MagicFormat
	def magic
		self.file_magic.to_s(16).scan(/../).map {|pair| Integer("0x#{pair}").chr }.join
	end
end

class FDatHeader
	include MagicFormat
	def to_s()
		"<struct FDatHeader file_magic=#{self.magic}, file_version=#{self.file_version}, fileid min/max: #{self.fileid_min}-#{self.fileid_max} (#{self.fileid_max - self.fileid_min} fileids, #{self.fileid_min_req}-#{self.fileid_max_req}), files_used=#{self.files_used}, files_allocated=#{self.files_allocated}>"
	end
end

class SDatHeader
	include MagicFormat
	def to_s()
		"<struct SDatHeader file_magic=#{self.magic}, file_version=#{self.file_version}, first_segment=#{self.first_segment}, next_free_segment=#{self.next_free_segment}>"
	end
end

def read_fdat_header(file)
	h = FDatHeader.new
	h.file_magic, h.file_version, _, h.fileid_min, h.fileid_max, h.fileid_min_req, h.fileid_max_req, h.files_used, h.files_allocated = file.read(36).unpack("QSSLLLLLL")
	h
	#FDatHeader.new(*file.read(26).unpack('QSIIQ'))
end

def read_sdat_header(file)
	h = SDatHeader.new
	h.file_magic, h.file_version, _, h.first_segment, h.next_free_segment = file.read(32).unpack("QSSLL")
	h
	#SDatHeader.new(*file.read(18).unpack('QSSII'))
end

def read_fileid(fdat)
	f = FileID.new
	f.fileid, f.size_used, f.page_alloc, _, f.first_segments, f.cur_segments = *fdat.read(16).unpack("VSCCVV")
	f
rescue
	nil
end

require 'cgi'
def generate_nzb(sdat, fileid, segments)
	puts "<!-- FileID: #{fileid.fileid} -->"
	puts "<segments>"
	segments.each do |segment|
		puts "  <segment bytes=\"#{segment.size}\" number=\"#{segment.segment}\">#{CGI.escapeHTML(segment.msgid)}</segment>"
	end
	puts "</segments>"
end

def fileid_binsearch(target, fdat, fdat_header) # {{{
	xend = fdat_header.files_used
	start = 0
	mid = 0

	loop do
		length = xend - start
		mid = start + (length >> 1)

		fdat.pos = 4096 + mid * 16
		test = read_fileid(fdat)
		if !test
			puts "Read returned nil"
		end
		if target == test.fileid
			return test
		elsif target < test.fileid
			xend = mid
		else
			start = mid + 1
		end
		break if length == 0
	end
end # }}}

# open and scan headers {{{
<<<<<<< .mine
fdat = File.new('testout.fdat')
sdat = File.new('testout.sdat')
=======
fdat = File.new('/tank/MessageIDs_20090317.fdat')
sdat = File.new('/tank/MessageIDs_20090317.sdat')
>>>>>>> .r8634

puts "Read fdat header"
fdat_header = read_fdat_header(fdat)
puts fdat_header
puts "Read sdat header"
sdat_header = read_sdat_header(sdat)
puts sdat_header

dump = false
dump = ARGV.shift if ARGV.first == 'dump'

all_fileids = []
fileids = []
if ARGV.size == 0
	fdat.pos = 4096
	all_fileids = []
	fdat_header.files_used.times do
		f = read_fileid(fdat)
		break if f.fileid.zero?
		all_fileids << f
	end
	puts "Index contains #{all_fileids.size} files"
	if dump
		puts "Dumping entire database"
		fileids = all_fileids
	else
		puts "Selecting 50 random fileids"
		all_fileids = all_fileids.sort_by { rand }[0...50].map {|x| x.fileid }
	end
else
	all_fileids = ARGV.map {|a| Integer(a) }
end

if !dump
	puts "Looking up fileids in index"
	all_fileids.each do |fileid|
		r = fileid_binsearch(fileid.to_i, fdat, fdat_header)
		if r
			fileids << r
		else
			puts "Not found: #{fileid}"
		end
	end
	puts "Searching"
end
# }}}

STDOUT.sync = true
filecount = 0
segcount = 0
memoized_host_bytes_saved = 0

page_dist = Hash.new {|h,k| h[k] = 0 }

at_exit do
	puts
	puts "Files: #{filecount}, Segments: #{segcount}, Files/Segment: #{segcount/filecount.to_f}"
	puts "Page distribution: #{page_dist.keys.sort.map {|x| "#{x}: #{page_dist[x]}" }.join(", ")}"
	puts "Proposed saving host in a magic struct segment would save: #{memoized_host_bytes_saved} bytes"
end

fileids.each do |fileid|
	#p fileid
	filecount += 1
	print "\r#{filecount}" if filecount % 500 == 0
	sdat.pos = fileid.first_segments * 4096
	segments = []
	pages = 0

	loop do
		pages += 1
		begin
			segs = Segments.new(*sdat.read(8).unpack("VCCS"))
		rescue
			puts sdat.pos
			break
		end
		segs.segments = []
		#p segs
		if segs.segment_magic != 78 # ?N
			puts "Segment magic incorrect: #{segs}"
			exit
		end

		last_host = nil
		segs.segment_count.times do
			apos = sdat.pos
			seg = Segment.new(*sdat.read(4 + 4 + 2 + 1).unpack("VVSC"))
			seg.msgid = sdat.read(seg.msgid_len)
			bpos = sdat.pos
			if apos / 4096 != bpos / 4096
				puts "Segment overflows page boundry: #{apos / 4096} -> #{bpos / 4096} (#{apos} -> #{bpos})"
				p seg
				exit
			end
			segments << seg
			if seg.msgid =~ /[\xf0-\xff\x00-\x06\e]/
				puts "Suspect segment: #{seg.msgid.dump}"
				puts "Position: #{sdat.pos - (4 + 4 + 2 + 1)}"
				exit
			end
		end

		last_host = nil
		segments.sort_by {|seg| seg.msgid.split('@', 2)[1] }.each do |seg|
			host = seg.msgid.split('@', 2)[1]
			if host == last_host
				memoized_host_bytes_saved += host.size
			else
				last_host = host
				# cost of storing it
				memoized_host_bytes_saved -= 11 + host.size
			end
		end

		if segs.next_segments.zero?
			break
		else
			#puts "Next segments on page #{segs.next_segments}"
			sdat.pos = segs.next_segments * 4096
		end
	end
	segcount += segments.size
	page_dist[pages] += 1

	if false
	hosts = Hash.new {|h,k| h[k] = 0 }
	segments.each do |seg|
		hosts[seg.msgid.split('@', 2)[1]] += 1
	end
	if hosts.size > 1
		puts
		puts "#{hosts.size} distinct hosts in message-id's for file #{fileid.fileid}"
		puts hosts.keys.sort.map {|x| "#{x}: #{hosts[x]}" }.join(", ")
	end
	end

	if check_db
	segindex = Hash.new {|h,k| h[k] = [] }
	segments.each {|s| segindex[s.segment] << s }
	res = DB.execute("SELECT mid_msgid, mid_fileid, mid_segment, mid_date, mid_bytes FROM MessageIDs_20090317
	                  WHERE mid_fileid=#{fileid.fileid} ORDER BY mid_segment")

	r = []
	while row = res.fetch_hash
		r << row
	end
	res.finish

	if r.size != segments.size
		puts "Database has different number of segments for #{fileid.fileid}: Us: #{segments.size}, SQL: #{r.size}"
	end

	r.each_with_index do |s, i|
		segs = segindex[s['mid_segment'].to_i] # segments[i]

		errs = []
		errs = segs.map do |seg|
			e = []
			if seg.nil?
				e << "Missing record: file #{fileid.fileid} segment #{i}, MySQL has: #{s['mid_segment']}"
			end

			if s['mid_msgid'] != seg.msgid
				e << "Corrupt msgid: file #{fileid.fileid} segment #{seg.segment}, Us: #{seg.msgid.dump}, SQL: #{s['mid_msgid'].dump}"
			end

			if s['mid_segment'].to_i != seg.segment
				e << "Segment number incorrect: file #{fileid.fileid} segment #{i}, Us: #{seg.segment}, SQL: #{s['mid_segment']}"
			end

			if s['mid_date'].to_i != seg.date
				e << "Segment date incorrect: file #{fileid.fileid} segment #{i}, Us: #{seg.date}, SQL: #{s['mid_date']}"
			end

			if s['mid_bytes'].to_i != seg.size
				e << "Segment size incorrect: file #{fileid.fileid} segment #{i}, Us: #{seg.size}, SQL: #{s['mid_bytes']}"
			end
			e
		end
		unless errs.any? {|e| e.empty? }
			puts "All candidate segments errored:"
			puts errs.map {|e| e.join("\n") }.join("\n")
		end
	end
	end
<<<<<<< .mine
	#segments = segments.sort_by {|s| s.segment }
	#generate_nzb(sdat, fileid, segments)
=======
#	generate_nzb(sdat, fileid, segments)
>>>>>>> .r8634
end

