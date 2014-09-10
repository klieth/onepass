require "OnePass/version"
require "openssl"
require "sqlite3"
require "json"

module OnePass
  class VerifyException < Exception
  end

  class Opdata
    attr_reader :data

    class InvalidException < Exception
    end

    def initialize(buf, key, mac)
      if buf[0..7] != "opdata01"
        raise OnePass::Opdata::InvalidException.new("Header was incorrect")
      end
      @length = buf[8..15].unpack("V")[0]
      @mac = buf[-32..-1]
      if OpenSSL::HMAC.digest(OpenSSL::Digest::SHA256.new, mac, buf[0..-33]) != @mac
        raise OnePass::VerifyException.new("MAC doesn't match; verify failed. Check your encryption/mac keys.")
      end
      @data = decrypt(buf[16..-33], key)[-1*@length..-1]
    end

    private

    def decrypt(data, key)
      @iv = data[0..15]
      cipher = OpenSSL::Cipher::AES.new(256, :CBC)
      cipher.decrypt
      cipher.padding = 0
      cipher.iv = @iv
      cipher.key = key
      return cipher.update(data[16..-1]) + cipher.final
    end
  end

  class Manager
    def initialize(master_password, path = nil)
      begin
        # copy db locally
        path ||= "#{ENV["HOME"]}/Library/Application Support/1Password 4/Data/OnePassword.sqlite"
        raise "Can't find sqlite db at #{path}" unless File.exist? path
        FileUtils.cp(path, ".")

        # read profile data
        db = SQLite3::Database.new "OnePassword.sqlite"
        # FIXME: This assumes a single profile; it's unclear from the documentation whether it's possible to have multiple of these
        profile = db.execute "SELECT master_key_data,overview_key_data,salt,iterations FROM profiles"
        profile = profile[0]
        digest = OpenSSL::Digest::SHA512.new

        # derive the key from the password
        derived_key = OpenSSL::PKCS5.pbkdf2_hmac(master_password, profile[2], profile[3], 64, digest)
        derived_encryption_key = derived_key[0..31]
        derived_mac_key = derived_key[32..-1]

        # try to unlock profile data. return fail if failed login
        overview_key_data = OnePass::Opdata.new(profile[1], derived_encryption_key, derived_mac_key)
        overview_key = OpenSSL::Digest::SHA512.new.digest(overview_key_data.data)
        overview_encryption_key, overview_mac_key = overview_key[0..31], overview_key[32..-1]

        # load overview opdata into object based format
        @overviews = []
        db.execute "SELECT items.key_data, items.overview_data, item_details.data FROM items INNER JOIN item_details ON items.id=item_details.item_id;" do |row|
          overview = OnePass::Opdata.new(row[1], overview_encryption_key, overview_mac_key)
          json = JSON.parse(overview.data).merge({"key_data"=>row[0],"data"=>row[2]})
          @overviews << json
        end

        master_key_data = OnePass::Opdata.new(profile[0], derived_encryption_key, derived_mac_key)
        master_key = OpenSSL::Digest::SHA512.new.digest(master_key_data.data)
        @master_encryption_key, @master_mac_key = master_key[0..31], master_key[32..-1]

        # delete the local copy of the database
        db.close
      ensure
        FileUtils.rm Dir.glob("OnePassword.sqlite*")
      end
    end

    def load_all_regex(re)
      all = []
      @overviews.each do |overview|
        all << overview if /#{re}/.match(overview["title"])
      end
      return all unless all.empty?
      return nil
    end

    def decrypt(overview)
      key_data = overview["key_data"][0..-33]
      mac = overview["key_data"][-32..-1]
      if OpenSSL::HMAC.digest(OpenSSL::Digest::SHA256.new, @master_mac_key, key_data) != mac
        raise VerifyException.new("The item's encryption key couldn't be verified.")
      end
      cipher = OpenSSL::Cipher::AES.new(256, :CBC)
      cipher.decrypt
      cipher.padding = 0
      cipher.iv = key_data[0..15]
      cipher.key = @master_encryption_key
      key_data = cipher.update(key_data[16..-1]) + cipher.final
      return JSON.parse(OnePass::Opdata.new(overview["data"],key_data[0..31],key_data[32..-1]).data)["password"]
    end
  end
end
