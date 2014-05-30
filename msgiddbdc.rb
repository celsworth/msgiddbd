#!/usr/local/bin/ruby

$DEBUG = false

module MagicFormat # {{{
	def magic
		self.file_magic.to_s(16).scan(/../).map {|pair| Integer("0x#{pair}").chr }.join
	end
end # }}}
# require pp, hexdump, murmurhash {{{
require 'pp'
require 'hexdump'
MurmurSeed = 0x4E5A42

begin
require 'lib/murmur/murmurhash2'
rescue LoadError
	puts "LoadError loading MurmurHash2 extension, hashes will not be checked"
	def murmurhash2(data, seed)
		true
	end
else
include MurmurHash2
end # }}}

Segment = Struct.new(:date, :size, :segment, :msgid_len, :msgid)
Segments = Struct.new(:murmurhash2, :next_segments, :segment_magic, :segment_count, :size_used, :fileid, :segments)

FileID = Struct.new(:fileid, :file_magic, :page_alloc, :first_segments, :cur_segments)

FDatHeader = Struct.new(:file_magic, :file_version, :fileid_min, :fileid_max, :fileid_min_req, :fileid_max_req, :files_used, :files_allocated)
SDatHeader = Struct.new(:file_magic, :file_version, :first_segment, :next_free_segment)

LogfileEntry = Struct.new(:date, :magic, :segment)
LogfileHeader = Struct.new(:file_magic, :file_version, :flags, :reserved1, :row_count, :row_applied)
SegmentLocal = Struct.new(:fileid, :date, :size, :segment, :msgid_len, :reserved, :msgid)

class SegmentLocal
	def self.parse(io)
		self.new(*io.read(272).unpack('VVVSCCZ*'))
	end
end

class LogfileHeader # {{{
	include MagicFormat

	def self.parse(io)
		h = self.new(*io.read(28).unpack('QSCCQQ'))
		if h.file_magic != 0x4E5A424C4F474844
			puts "Header magic incorrect: 0x#{h.file_magic.to_s(16)} != 0x4E5A424C4F474844"
		end
		h
	end
end # }}}

class LogfileEntry # {{{
	def self.parse(io)
		e = self.new(*io.read(8).unpack('VV'))
		e.segment = SegmentLocal.parse(io)
		if e.magic != 0x4C4F4752
			puts "Segment magic incorrect: 0x#{e.magic.to_s(16)} != 0x4C4F4752"
		end
		msgid = e.segment.msgid
		if msgid =~ /[\xf0-\xff\x00-\x06\e]/ or msgid !~ /.+@.+/
			puts "Suspect segment: #{e.segment.msgid.dump}"
			puts "Position: ~#{io.pos}"
			exit
		end
		e
	rescue
		nil
	end
end # }}}

class Logfile
	attr_accessor :header
	def initialize(io)
		@header = LogfileHeader.parse(io)
		@io = io
	end

	def each
		@io.pos = 4096
		while e = LogfileEntry.parse(@io)
			yield e
		end
	end
end

class FileID # {{{
	include MagicFormat

	def self.parse(io, exact = false)
		f = FileID.new
		f.fileid = 0
		while f.fileid.zero?
			f.fileid, f.file_magic, f.page_alloc, _, f.first_segments, f.cur_segments = *io.read(16).unpack("VSCCVV")
			if f.fileid.zero? and !f.file_magic.zero?
				puts "FileID zero, magic nonzero at #{io.pos - 16}"
				exit
			end
			break if exact
		end
		if f.fileid.zero? or f.fileid.nil?
			return nil
		end
		if f.file_magic != ?Z | ?A << 8
			puts "FileID magic incorrect: #{f.file_magic}"
		end
		f
	rescue
		nil
	end
end # }}}

class FDatHeader # {{{
	include MagicFormat
	def inspect()
		"<struct FDatHeader file_magic=#{self.magic}, file_version=#{self.file_version}, fileid min/max: #{self.fileid_min}-#{self.fileid_max} (#{self.fileid_max - self.fileid_min} fileids, #{self.fileid_min_req}-#{self.fileid_max_req}), files_used=#{self.files_used}, files_allocated=#{self.files_allocated}>"
	end

	def self.parse(file)
		h = FDatHeader.new
		h.file_magic, h.file_version, _, h.fileid_min, h.fileid_max, h.fileid_min_req, h.fileid_max_req, h.files_used, h.files_allocated = file.read(36).unpack("QSSLLLLLL")
		h
	end
end # }}}

class FDat # {{{
	attr_reader :header, :fileids
	attr_reader :io

	def initialize(io)
		@io = io
		@header = FDatHeader.parse(io)
	end

	def load_index
		@io.pos = 4096
		@fileids = []
		@header.files_used.times do
			f = read_fileid
			break if f.fileid.zero?
			@fileids << f
		end
		puts "Index contains #{@fileids.size} files" if $DEBUG
	end

	def pos=(pos)
		@io.pos = pos
	end

	def each_fileid(&block)
		@io.pos = 4096
		while f = FileID.parse(@io)
			block.call(f)
		end
	end

	def find_file(target)
		rpos = target - header.fileid_min_req
		rpos *= 16
		rpos += 4096
		@io.pos = rpos
		f = FileID.parse(@io, true)
		if !f
			puts "FileID parse fail for #{target}"
			return
		end
		if f.fileid != target
			puts "Index looking got wrong fileid: #{f.fileid}, wanted #{target}"
		end
		f
	end

	def fileid_binsearch(target) # {{{
		xend = @header.files_used
		start = 0
		mid = 0

		loop do
			length = xend - start
			mid = start + (length >> 1)

			@io.pos = 4096 + mid * 16
			test = FileID.parse(@io)
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
end # }}}

class SDatHeader # {{{
	include MagicFormat
	def inspect()
		"<struct SDatHeader file_magic=#{self.magic}, file_version=#{self.file_version}, first_segment=#{self.first_segment}, next_free_segment=#{self.next_free_segment}>"
	end

	def self.parse(file)
		h = SDatHeader.new
		h.file_magic, h.file_version, _, h.first_segment, h.next_free_segment = file.read(32).unpack("QSSLL")
		h
	end
end # }}}

class SDat # {{{
	attr_reader :header
	attr_reader :io
	attr_reader :file_pages_count

	def initialize(io)
		@io = io
		@header = SDatHeader.parse(io)
		@file_pages_count = Hash.new {|h,k| h[k] = 0}
	end

	def scan_pages(verbose = false)
		max = File.size(@io.path) / 4096
		file = FileID.new
		1.upto(max) do |page|
			file.fileid = 0
			file.first_segments = page
			puts "page #{page}" if verbose
			begin
				segs, segments = segments_for_file(file, true)
				if verbose
					pp segs
					pp segments
				else
					print "\r#{segs.fileid}" if segs.fileid % 100 == 0
				end
			rescue
				p $!
			end
		end
	end

	def segments_for_file(fileid, recover = false)
		@io.pos = fileid.first_segments * 4096
		segments = []
		pages = 0
		segs = nil

		loop do
			pages += 1
			begin
				segs = Segments.new(*@io.read(16).unpack("VVCCSV"))
			rescue NoMethodError
				puts "File #{fileid.fileid} first_segments(#{pages}) page #{fileid.first_segments} (#{@io.pos}) unreadable"
				break
			rescue
				puts "segments_for_file failure at #{@io.pos}"
				break
			end
			if segs.segment_magic != 78 # ?N
				puts "Segment magic incorrect: #{fileid.inspect}, #{segs}"
				exit
			end

			opos = @io.pos
			#puts "Reading #{fileid.size_used} bytes at 0x#{@io.pos.to_s(16)} for hash"
			page = @io.read(segs.size_used)
			#puts "page: #{page.dump}"
			#page.hexdump
			#File.open("page.#{@io.pos / 4096}.dump",'w'){|f| f.write page }
			@io.pos = opos
			mh = murmurhash2(page, MurmurSeed)
			if mh != segs.murmurhash2
				puts "Segment murmurhash incorrect (stored #{segs.murmurhash2}, calc #{mh}): #{fileid}\n#{segs}"
			end

			last_host = nil
			segment_lengths = []
			page_start = opos - 16
			segs.segment_count.times do
				apos = @io.pos
				seg = Segment.new(*@io.read(4 + 4 + 2 + 1).unpack("VVSC"))
				seg.msgid = @io.read(seg.msgid_len)
				bpos = @io.pos
				segment_lengths << bpos - apos
				#puts "Segment: #{apos - (opos - 16)}-#{bpos - (opos - 16)}"
				if apos / 4096 != bpos / 4096
					puts "Segment overflows page boundry: #{apos / 4096} -> #{bpos / 4096} (#{apos} -> #{bpos})"
					p seg
					exit
				end
				segments << seg
				if seg.msgid =~ /[\xf0-\xff\x00-\x06\e]/
					puts "Suspect segment: #{seg.msgid.dump}"
					puts "Position: #{@io.pos - (4 + 4 + 2 + 1)}"
					exit
				end
			end

			if mh != segs.murmurhash2
				clen = 0
				segment_lengths.each_with_index do |len, i|
					clen += len
					nmh = murmurhash2(page[0, clen], MurmurSeed)
					if nmh == segs.murmurhash2
						puts "Found hash match at seg #{i}, pos #{clen}"
						break
					else
						puts "pos=#{len}"
					end
				end
			end

			if segs.next_segments.zero?
				break
			else
				#puts "Next segments on page #{segs.next_segments}"
				@io.pos = segs.next_segments * 4096
			end
		end
		@file_pages_count[pages] += 1
		segments = segments.sort_by {|s| s.segment }
		if recover
			[segs, segments]
		else
			segments
		end
	end
end # }}}

class SegmentTable
	attr_reader :fdat, :sdat

	def initialize(index, data)
		@fdat = FDat.new(File.new(index))
		@sdat = SDat.new(File.new(data))
	end

	def name
		File.basename(@sdat.io.path).gsub /\.sdat$/, ""
	end

	def each_file(&block)
		@fdat.each_fileid do |file|
			if file.fileid < @fdat.header.fileid_min_req or file.fileid > @fdat.header.fileid_max_req
				puts "File #{file.fileid} in wrong table: #{@fdat.header}"
			end
			block.call(file)
		end
	end

	def segments_for_fileid(file)
		@sdat.segments_for_file(file)
	end

	def segments_for_file(id)
		r = @fdat.find_file(id.to_i)
		if r
			@sdat.segments_for_file(r)
		else
			puts "FileID #{id} not found in index"
			[]
		end
	end
end

class SegmentDatabase # {{{
	attr_reader :tables

	def initialize(dir)
		@dir = dir
		@tables = []
		@logs = []
		scan
	end

	def scan
		Dir[File.join(@dir, '*.fdat')].each do |f|
			@tables << SegmentTable.new(f, f.sub(/\.fdat/, '.sdat'))
		end
		# File.readlines(File.join(@dir, 'log.index')).each do |log|
		Dir[File.join(@dir, 'logs', '*')].each do |log|
			begin
				#@logs << Logfile.new(File.new(File.join(@dir, log.chomp)))
				@logs << Logfile.new(File.new(log))
			rescue Errno::ENOENT
				puts "#{log.chomp}: file not found, skipping"
			end
		end
		#@tables.each {|t| p t }
		#@logs.each {|l| p l }
	end

	def dump_logs
		@logs.each do |log|
			pp log.header
			log.each do |entry|
				p entry
			end
		end
	end

	def each_log_entry
		@logs.each do |log|
			p log
			log.each do |entry|
				yield entry
			end
		end
	end

	def file_selection(size = 50)
		sample = []
		while sample.size < size
			@tables.each do |table|
				table.fdat.load_index unless table.fdat.fileids
				l = table.fdat.fileids.length
				s = rand(l)
				puts "Sample: #{s}, #{table.fdat.fileids[s]}"
				sample << table.fdat.fileids[s].fileid
				sample.compact.sort.uniq
			end
		end
		sample
	end

	def each_file_with_segments(&block)
		@tables.each do |table|
			table.each_file do |file|
				block.call(file, table.segments_for_fileid(file))
			end
		end
	end

	def segments_for_file(id)
		tables = @tables.select {|t| t.fdat.header.fileid_min <= id and t.fdat.header.fileid_max >= id }
		if tables.empty?
			puts "No tables with range for #{id}"
		elsif tables.size > 1
			puts "Ambiguous target table for #{id}"
			puts "Targets: #{tables.inspect}"
			tables.map {|table| table.segments_for_file(id) }.flatten
		else
			tables.first.segments_for_file(id)
		end
	end
end # }}}

require 'dbi'
SQL = DBI.connect("DBI:Mysql:newzDog:db4", 'newzDog', '$h1tePwd')
DB = SegmentDatabase.new('/db')

class SegmentValidator # {{{
	def initialize(check_db = false)
		@filecount = 0
		@segcount = 0
		@check_db = check_db
		@db = ::SQL

		if check_db
		end
	end

	def start
		@start = Time.new
	end

	def finish
		@finish = Time.new
		delta = @finish.to_f - @start.to_f
		puts "%d files, %d segments in %.2f" % [@filecount, @segcount, delta]
		puts "%.2f files/sec, %.2f segs/sec" % [@filecount / delta, @segcount / delta]
	end

	def validate(fileid, segments)
		@filecount += 1
		@segcount += segments.size
		ok = !segments.empty?

		return ok unless @check_db

		segindex = Hash.new {|h,k| h[k] = [] }
		segments.each {|s| segindex[s.segment] << s }
		res = SQL.execute("SELECT mid_msgid, mid_fileid, mid_segment, mid_date, mid_bytes FROM MessageIDs
											WHERE mid_fileid=#{fileid.fileid} ORDER BY mid_segment")

		r = []
		while row = res.fetch_hash
			r << row
		end
		res.finish

		if r.size != segments.size
			puts "Database has different number of segments for #{fileid.fileid}: Us: #{segments.size}, SQL: #{r.size}"
			ok = false
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
				ok = false
			end
		end

		ok
	end
end # }}}

require 'cgi'
NewsFile = Struct.new(:FileID, :Subject, :Date, :Author, :Groups)

class NZB # {{{
	def initialize(out)
		@out = out
		@start = Time.new
		@bytes = 0
		@files = 0
		@segments = 0
	end

	def h(txt)
		CGI.escapeHTML(txt)
	end

	def out(txt)
		@bytes += txt.size
		@out.write(txt)
	end

	def header
		out <<EOH
<?xml version="1.0" encoding="iso-8859-1" ?>
<!DOCTYPE nzb PUBLIC "-//newzBin//DTD NZB 1.0//EN" "http://www.newzbin.com/DTD/nzb/nzb-1.0.dtd">
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
EOH
	end

	def file(file, segs)
		@files += 1
		out <<EOF
	<file subject="#{h file.Subject}" date="#{file.Date}" poster="#{file.Author}">
		<groups>
EOF
		file.Groups.each do |group|
			out "\t\t\t<group>#{h group}</group>\n"
		end
		out "\t\t</groups>\n"
		segments(segs)

		out <<EOF
	</file>
EOF
	end

	def segments(segs)
		out "\t\t<segments>\n"
		@segments += segs.size
		segs.each do |segment|
			out "\t\t\t<segment bytes=\"#{segment.size}\" number=\"#{segment.segment}\">#{h segment.msgid}</segment>\n"
		end
		out "\t\t</segments>\n"
	end

	def footer
		@finish = Time.new
		out <<EOF
	<!-- Generated by Newzbin.com - #{Time.new.to_i} -->
	<!-- #{@bytes} bytes generated in #{'%.2f' % [@finish.to_f - @start.to_f]} seconds -->
	<!-- #{@files} files amd #{@segments} segments in this NZB -->
</nzb>
EOF
	end
end # }}}

class NZBClient # {{{
	def process(client)
			ids = client.gets.split(",")
			ids.map! {|x| Integer(x) }

			res = SQL.execute("SELECT FileID,Subject,Date,a_name FROM News LEFT JOIN Authors ON (News.AuthorID = Authors.a_id) WHERE FileID IN (?)", ids)
			@files = {}
			while row = res.fetch_hash
				f = NewsFile.new(*row.values_at('FileID', 'Subject', 'Date', 'a_name'))
				f.Groups = []
				@files[row['FileID'].to_i] = f
			end
			res.finish

			res = SQL.execute("SELECT FileID,GroupName FROM FileGroup LEFT JOIN Groups ON (FileGroup.GroupID=Groups.GroupID) WHERE FileGroup.FileID IN (?)", ids)
			while row = res.fetch_hash
				@files[row['FileID'].to_i].Groups << row['GroupName']
			end
			res.finish
			nzb = NZB.new(client)
			nzb.header
			ids.each do |id|
				if @files.key? id
					segs = DB.segments_for_file(id)
					if segs.nil? or segs.empty?
						client.write("\n\t<!-- Couldn't find segments for FileID #{id} -->\n")
					else
						nzb.file(@files[id], segs)
					end
				else
					client.write("\n\t<!-- Couldn't find FileID #{id} :( -->\n")
				end
			end
			nzb.footer
			client.write("\000")
	rescue => e
			p e
			puts e.message
			puts e.backtrace.join("\n")
	end
end # }}}

handler = NZBClient.new
validator = SegmentValidator.new

def validate_files_with_tables(files, tables)
	filesegs = {}
	ids = files.map {|file, segments| file.fileid }
	validate_fileids_with_tables(ids, tables)
end

def validate_fileids_with_tables(ids, tables)
	files = {}
	ids.each do |id|
		segs = DB.segments_for_file(id)
		files[id] = {}
		segs.each {|seg| files[id][seg.msgid] = seg }
	end
	sql = tables.map {|table| "(SELECT * FROM #{table} WHERE mid_fileid IN (#{ids.join(",")}))" }.join(" UNION ")
	stmt = SQL.execute(sql)
	row = 0
	while s = stmt.fetch_hash
		row += 1
		seg = files[s['mid_fileid'].to_i].delete(s['mid_msgid'])
		unless seg
			puts "Missing segment for fileid #{s['mid_fileid']}: #{s['mid_msgid']}"
		else
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
		end
	end
	files.each do |id, segments|
		unless segments.empty?
			puts "Spurious MessageIDs in file #{id}: #{segments.inspect}"
		end
	end
	if row.zero?
		puts "SELECT missing fileids!"
	end
	stmt.finish
end

def mysql_tables_for_files(fileids)
	stmt = SQL.execute("SELECT tablename from MessageID_Ranges WHERE
	min_fileid <= ? AND max_fileid >= ?", fileids.max, fileids.min)
	tables = []
	while s = stmt.fetch_hash
		tables << s['tablename']
	end
	stmt.finish
	tables
end

STDOUT.sync = true
case ARGV.first
when 'spewlogs'
	DB.dump_logs
when 'dumplogs'
	validator.start
	at_exit { puts ; validator.finish }
	file = FileID.new
	i = 0
	DB.each_log_entry do |entry|
		i += 1
		file.fileid = entry.segment.fileid
		print "\r#{file.fileid}" if i % 50 == 0
		unless validator.validate(file, [entry])
			print
			puts "Error detected: #{entry.inspect}"
			print "Enter to continue: "
			STDIN.gets
		end
	end
	puts "Last fileid: #{file.fileid}"
when 'scansdat'
	table = ARGV[1] or raise ArgumentError.new("Table name not provided")
	debug = ARGV[2] == '-d'
	DB.tables.select {|t| t.name == table }.each do |t|
		t.sdat.scan_pages(debug)
	end
when 'dumptable'
	table = ARGV[1] or raise ArgumentError.new("Table name not provided")
	validator.start
	at_exit { puts ; validator.finish }
	i = 0
	min_fileid = 1 / 0.0
	max_fileid = 0
	puts "Dumping #{table}"
	DB.tables.select {|t| t.name == table }.each do |t|
		p t
		t.each_file do |file|
			min_fileid = file.fileid if file.fileid < min_fileid
			max_fileid = file.fileid if file.fileid > max_fileid
			segments = t.segments_for_fileid(file)
			i += 1
			print "\r#{file.fileid}" if i % 50 == 0
			unless validator.validate(file, segments)
				print
				puts "Error detected: #{file.inspect}, #{segments.inspect}"
			#	print "Enter to continue: "
			#	STDIN.gets
			end
		end
		puts "Min: #{min_fileid}, Max: #{max_fileid}"
	end
when 'dump'
	validator.start
	at_exit { puts ; validator.finish }
	i = 0
	DB.each_file_with_segments do |file, segments|
		i += 1
		print "\r#{file.fileid}" if i % 50 == 0
		unless validator.validate(file, segments)
			print
			puts "Error detected: #{file.inspect}, #{segments.inspect}"
			print "Enter to continue: "
			STDIN.gets
		end
	#	generate_nzb(file, segments)
	end
when 'countpages'
	i = 0
	DB.each_file_with_segments do |file, segments|
		i += 1
		print "\r#{file.fileid}" if i % 50 == 0
	end
	puts
	DB.tables.each do |table|
		puts "Table: #{table.inspect}"
		counts = table.sdat.file_pages_count.to_a.sort_by {|x| x.first }
		counts.each do |pages,files|
			puts "#{pages}: #{files}"
		end
		puts ('-' * 50)
	end
when "server"
require 'socket'
Port = 20000
	puts "Service going up on #{Port}"
	server = TCPServer.new(Port)
	while client = server.accept
		begin
			handler.process(client)
		ensure
			client.close
		end
	end
when "verifyrange"
	ARGV.shift
	min = Integer(ARGV.shift)
	max = Integer(ARGV.shift)
	files = []
	i = 0
	total = 0
	start = Time.new
	min.upto(max) do |id|
		files << id
		if files.size >= 50
			total += files.size
			print "\r#{files.min} - #{files.max} (#{(total / (Time.new - start)).to_i}/sec)"
			t = mysql_tables_for_files(files)
			validate_fileids_with_tables(files, t)
			files.clear
		end
	end
	if files.size > 0
		t = mysql_tables_for_files(files)
		validate_fileids_with_tables(files, t)
	end
when "fileidholes"
	ARGV.shift
	min = Integer(ARGV.shift)
	max = Integer(ARGV.shift)
	files = []
	i = 0
	min.upto(max) do |fileid|
		print "\r#{fileid}" if i % 50 == 0
		i += 1
		segs = DB.segments_for_file(fileid)
		if segs
			validator.validate(fileid, segs)
		else
			puts "Missing: #{fileid}"
		end
	end
when "verify"
	ARGV.shift
	files = []
	done_files = 0
	total_files = 0
	tables = ARGV
	tables.each do |table|
		stmt = SQL.execute("SELECT COUNT(*) FROM #{table}")
		total_files += stmt.fetch.first
		stmt.finish
	end

	i = 0
	DB.each_file_with_segments do |file, segments|
		i += 1
		print "\r#{file.fileid}" if i % 50 == 0
		done_files += 1
		files << [file, segments]
		if files.size > 50
			validate_files_with_tables(files, tables)
			files.clear
		end	
	end
	validate_files_with_tables(files, tables)
	if done_files != total_files
		puts "Warning: expected #{total_files} files, processed #{done_files}"
	end
when "select"
	puts DB.file_selection.join(",")
when /^\d+$/
	fileid = ARGV.shift.to_i
	segs = DB.segments_for_file(fileid)
	validator.validate(fileid, segs) if segs
	pp segs
end

