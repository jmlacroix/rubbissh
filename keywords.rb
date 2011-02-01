require 'rubygems'
require 'pp'

def build_keywords_list(file)
  keywords = {}
  File.open(file).each_line do |s|
    s.chomp!
    r = s.gsub(/([a-z])([A-Z])/, '\1_\2')
    r = r.gsub(/([A-Z0-9]{3,6})([A-Z][^_])/, '\1_\2')
    keywords[r.downcase.to_sym] = s
  end
  keywords
end

print "KEYWORDS = "
pp build_keywords_list('keywords.txt')

