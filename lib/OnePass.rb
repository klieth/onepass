require "OnePass/version"
require "openssl"
require "sqlite3"
require "json"
require "tempfile"
require "cfpropertylist"

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
      @length = buf[8..15].unpack("Q<")[0]
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
      path ||= "#{ENV["HOME"]}/Library/Application Support/1Password 4/Data/OnePassword.sqlite"
      raise "Can't find sqlite db at #{path}" unless File.exist? path

      db_filename = File.basename(path)
      dir_path = File.dirname(path)

      # 1Password keeps the sqlite db open in exclusive mode. So we copy it to
      # a tempdir and use that.
      #
      # Note that Dir.mktmpdir will clean up after itself when
      # passed a block.
      Dir.mktmpdir('OnePass') do |tmpdir|
        FileUtils.cp_r("#{dir_path}/.", tmpdir)
        sqlite_file = File.join(tmpdir, db_filename)

        # roll the main db forward using write-ahead-log.
        db = SQLite3::Database.new(sqlite_file)
        db.execute "VACUUM;"

        @master_keys = []
        @overview_keys = []
        @overviews = []
        # read master profile
        master_profile = db.execute "SELECT id,master_key_data,overview_key_data,salt,iterations FROM profiles WHERE attributes_data IS NULL"
        raise "Found more than one master profile!" unless master_profile.length == 1
        master_profile.flatten!
        master_profile_id = master_profile[0]

        # derive the key from the password
        derived_key = OpenSSL::PKCS5.pbkdf2_hmac(master_password, master_profile[3], master_profile[4], 64, OpenSSL::Digest::SHA512.new)
        derived_encryption_key = derived_key[0..31]
        derived_mac_key = derived_key[32..-1]

        # Obtain the master profile master keys
        master_key_data = OnePass::Opdata.new(master_profile[1], derived_encryption_key, derived_mac_key)
        master_key = OpenSSL::Digest::SHA512.new.digest(master_key_data.data)
        @master_keys[master_profile_id] = {enc_key: master_key[0..31], mac_key: master_key[32..-1]}

        # Obtain the master profile overview keys
        overview_key_data = OnePass::Opdata.new(master_profile[2], derived_encryption_key, derived_mac_key)
        overview_key = OpenSSL::Digest::SHA512.new.digest(overview_key_data.data)
        @overview_keys[master_profile_id] = { enc_key: overview_key[0..31], mac_key: overview_key[32..-1] }

        # Obtain keys for remaining profiles
        db.execute "SELECT id,attributes_data FROM profiles WHERE attributes_data IS NOT NULL" do |profile|
          attributes_data = OnePass::Opdata.new(profile[1], @overview_keys[master_profile_id][:enc_key], @overview_keys[master_profile_id][:mac_key])
          plist = CFPropertyList.native_types(CFPropertyList::List.new(:data => attributes_data.data).value)
          overview_key_data = plist['$objects'][plist['$top']['overviewKey']]
          overview_key = OpenSSL::Digest::SHA512.new.digest(overview_key_data)
          @overview_keys[profile[0]] = { enc_key: overview_key[0..31], mac_key: overview_key[32..-1] }
          master_key_data = plist['$objects'][plist['$top']['masterKey']]
          master_key = OpenSSL::Digest::SHA512.new.digest(master_key_data)
          @master_keys[profile[0]] = { enc_key: master_key[0..31], mac_key: master_key[32..-1] }
        end

        # load overview opdata into object based format. overviews are stored decrypted for use later.
        # the encrypted data for the keys is included, but is not decrypted unless requested later
        db.execute "SELECT items.profile_id, items.key_data, items.overview_data, item_details.data FROM items INNER JOIN item_details ON items.id=item_details.item_id" do |item|
          overview = OnePass::Opdata.new(item[2], @overview_keys[item[0]][:enc_key], @overview_keys[item[0]][:mac_key])
          json = JSON.parse(overview.data).merge({profile: item[0], key_data: item[1], data: item[3]})
          @overviews << json
        end

        db.close

        # tmpdir removed when block exits
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

    def decrypt(overview, all = nil)
      key_data = overview[:key_data][0..-33]
      mac = overview[:key_data][-32..-1]
      profile = overview[:profile]
      if OpenSSL::HMAC.digest(OpenSSL::Digest::SHA256.new, @master_keys[profile][:mac_key], key_data) != mac
        raise VerifyException.new("The item's encryption key couldn't be verified.")
      end
      cipher = OpenSSL::Cipher::AES.new(256, :CBC)
      cipher.decrypt
      cipher.padding = 0
      cipher.iv = key_data[0..15]
      cipher.key = @master_keys[profile][:enc_key]
      key_data = cipher.update(key_data[16..-1]) + cipher.final
      results = JSON.parse(OnePass::Opdata.new(overview[:data],key_data[0..31],key_data[32..-1]).data)
      password = if results.has_key?("password")
        results["password"]
      elsif results.has_key?("fields")
        results["fields"].find { |h| h["designation"] == "password" }["value"]
      end
      return all ? results : password
    end
  end
end
