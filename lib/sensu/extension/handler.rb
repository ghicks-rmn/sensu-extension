gem "sensu-em"

require 'net/http'
require "eventmachine"
require "sensu/extension/constants"

module Sensu
  module Extension
    class Handler < Base

      def options
        return @options if @options
        @options = {
          :filter_disabled     => false,
          :filter_repeated     => false,
          :filter_silenced     => false,
          :filter_dependencies => false
        }
        if @settings[name.to_sym].is_a?(Hash)
          @options.merge!(@settings[name.to_sym])
        end
        @options
      end

      def net_http_req_class(method)
        case method.to_s.upcase
        when 'GET'
          Net::HTTP::Get
        when 'POST'
          Net::HTTP::Post
        when 'DELETE'
          Net::HTTP::Delete
        when 'PUT'
          Net::HTTP::Put
        end
      end

      def api_request(method, path, &blk)
        http = Net::HTTP.new(@settings[:api][:host], @settings[:api][:port])
        req = net_http_req_class(method).new(path)
        if @settings[:api][:user] && @settings[:api][:password]
          req.basic_auth(@settings[:api][:user], @settings[:api][:password])
        end
        yield(req) if block_given?
        http.request(req)
      end

      # Filter events that should be ignored.
      # These will only run if explicitly enabled in the "options" hash.
      def filter
        if not @filters
          @filters = []
          @filters << method(:filter_disabled)     if options[:filter_disabled]
          @filters << method(:filter_repeated)     if options[:filter_repeated]
          @filters << method(:filter_silenced)     if options[:filter_silenced]
          @filters << method(:filter_dependencies) if options[:filter_dependencies]
        end
        @filters.each do |method|
          result, message = method.call
          if result == false
            return result, message
          end
        end
        return true, ''
      end

      # Filter events with 'alert' set to false.
      def filter_disabled
        if @event[:check][:alert] == false
          return false, 'alert disabled'
        end
        return true, ''
      end

      # Filter events that haven't met their occurrences or refresh criteria.
      def filter_repeated
        defaults = {
          :occurrences => 1,
          :interval    => 30,
          :refresh     => 1800
        }

        if settings['sensu_plugin'].is_a?(Hash)
          defaults.merge!(settings['sensu_plugin'])
        end

        occurrences = @event[:check][:occurrences] || defaults[:occurrences]
        interval    = @event[:check][:interval]    || defaults[:interval]
        refresh     = @event[:check][:refresh]     || defaults[:refresh]
        if @event[:occurrences] < occurrences
          return false, "not enough occurrences (need #{defaults[:occurrences]})"
        end
        if @event[:occurrences] > occurrences && @event[:action] == 'create'
          number = refresh.fdiv(interval).to_i
          unless number == 0 || @event[:occurrences] % number == 0
            return false, 'only handling every ' + number.to_s + ' occurrences'
          end
        end
        return true, ''
      end

      # Given a stash name, return true if it exists.
      def stash_exists?(path)
        api_request(:GET, '/stash' + path).code == '200'
      end

      # Filter events that have been stashed (by client, check, or combination of the two).
      def filter_silenced
        stashes = [
          ['client', '/silence/' + @event[:client][:name]],
          ['check', '/silence/' + @event[:client][:name] + '/' + @event[:check][:name]],
          ['check', '/silence/all/' + @event[:check][:name]]
        ]
        stashes.each do |(scope, path)|
          begin
            timeout(2) do
              if stash_exists?(path)
                return false, scope + " alerts silenced (#{path})"
              end
            end
          rescue Timeout::Error
            return false, 'timed out while attempting to query the sensu api for a stash'
          end
        end
        return true, ''
      end

      # Given a check and client name, return true if it exists.
      def event_exists?(client, check)
        api_request(:GET, '/event/' + client + '/' + check).code == '200'
      end

      # Filter events that have dependencies that are already failing.
      def filter_dependencies
        if @event[:check].has_key?(:dependencies)
          if @event[:check][:dependencies].is_a?(Array)
            @event[:check][:dependencies].each do |dependency|
              begin
                timeout(2) do
                  check, client = dependency.split('/').reverse
                  if event_exists?(client || @event[:client][:name], check)
                    return false, "check dependency event exists (#{client || @event[:client][:name]}, #{check})"
                  end
                end
              rescue Timeout::Error
                return false, 'timed out while attempting to query the sensu api for an event'
              end
            end
          end
        end
        return true, ''
      end

      # Run the extension with a few safeties. This method wraps
      # run() with a begin;rescue, and duplicates data before passing
      # it to ensure the extension doesn't mutate the original. Do
      # not override this method!
      #
      # For handlers, the method also applies event filters if requested.
      #
      # @param data [Object, nil) to dup() and pass to run().
      # @param callback [Proc] to pass to run().
      def safe_run(data=nil, &callback)
        @event = data.dup
        result, message = filter
        if result == false
          callback.call(message, 0)
          return
        end
        begin
          data ? run(@event, &callback) : run(&callback)
        rescue => error
          callback.call(error.to_s, 2)
        end
      end

    end
  end
end
