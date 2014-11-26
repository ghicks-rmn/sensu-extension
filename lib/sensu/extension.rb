gem "sensu-em"

require "eventmachine"
require "sensu/extension/constants"

module Sensu
  module Extension
    class Base
      # @!attribute [rw] logger
      #   @return [Array] logger provided by Sensu.
      attr_accessor :logger

      # @!attribute [rw] settings
      #   @return [Array] settings hash provided by Sensu.
      attr_accessor :settings

      # Initialize the extension, call post_init() when the
      # eventmachine reactor starts up, stop() when it stops.
      def initialize
        EM.next_tick do
          post_init
        end
        EM.add_shutdown_hook do
          stop
        end
      end

      # Override this method to set the extension's name.
      def name
        "base"
      end

      # Override this method to set the extension's description.
      def description
        "extension description (change me)"
      end

      # Override this method to change the extension's definition, a
      # hash. You probably don't need to touch this. The hash must
      # contain :type ("extension") and :name.
      def definition
        {
          :type => "extension",
          :name => name
        }
      end

      # Override this method to do something immediately after the
      # eventmachine reactor is started. This method is great for
      # setting up connections etc.
      def post_init
        true
      end

      # Override this method to do something when the extension is
      # run, you must yield or call the callback with two parameters,
      # an output string and exit code.
      #
      # @param data [Object, nil] provided by Sensu.
      # @param callback [Proc] provided by Sensu, expecting to be
      #   called with two parameters, an output string and exit code.
      def run(data=nil, &callback)
        callback.call("noop", 0)
      end

      # Override this method to do something when the eventmachine
      # reactor stops, such as connection or file cleanup.
      def stop
        true
      end

      # Retrieve the definition object corresponding to a key, acting
      # like a Hash object. Do not override this method!
      #
      # @param key [String, Symbol]
      # @return [Object] value for key.
      def [](key)
        definition[key.to_sym]
      end

      # Check to see if the definition has a key. Do not override this
      # method!
      #
      # @param key [String, Symbol]
      # @return [TrueClass, FalseClass]
      def has_key?(key)
        definition.has_key?(key.to_sym)
      end

      # Run the extension with a few safeties. This method wraps
      # run() with a begin;rescue, and duplicates data before passing
      # it to ensure the extension doesn't mutate the original. Do
      # not override this method in your extensions!
      #
      # @param data [Object, nil) to dup() and pass to run().
      # @param callback [Proc] to pass to run().
      def safe_run(data=nil, &callback)
        begin
          data ? run(data.dup, &callback) : run(&callback)
        rescue => error
          callback.call(error.to_s, 2)
        end
      end

      # Determine classes that have inherited this class, used by the
      # extension loader. Do not override this method!
      #
      # @return [Array<object>]
      def self.descendants
        ObjectSpace.each_object(Class).select do |klass|
          klass < self
        end
      end
    end

    # Create an extension class for each category from Base.
    CATEGORIES.each do |category|
      next if [:handlers].include? category # Handler subclass is explicitly defined in sensu/extension/handler.
      extension_type = category.to_s.chop
      Sensu::Extension.const_set(extension_type.capitalize, Class.new(Base))
    end
  end
end

require "sensu/extension/handler"

