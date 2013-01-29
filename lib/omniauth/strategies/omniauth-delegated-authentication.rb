require 'omniauth'

module OmniAuth
  module Strategies
    class DelegatedAuthentication
      include OmniAuth::Strategy

      args [:app_id, :app_secret]

      option :client_options, {}

      attr_accessor :consent_token

      # AFIK there is no DelegatedAuthentication gem currently available, so this developer
      # strategy assumes that this class will be overwritten by the provider strategy
      def client
        ::DelegatedAuthentication.new(options[:app_id], options[:app_secret], nil, nil, options[:privacy_url], callback_url)
      end

      def callback_url
        full_host + script_name + callback_path
      end

      # Assumes that the provider strategy client method includes `getConsentUrl`
      def request_phase
        redirect client.getConsentUrl(options[:scope], nil, callback_url, nil)
      end

      def callback_phase
        if request.params['action'] == "cancel"
          raise CallbackError.new(request.params['action'], request.params['ResponseCode'])
        end

        self.consent_token = process_consent_token
        self.consent_token = client.refreshConsentToken(self.consent_token) unless consent_token.isValid?

        super
      rescue CallbackError => e
        fail!(:invalid_credentials, e)
      end

      protected

      def process_consent_token
        consent_token = request.params['ConsentToken']
        client.processConsentToken(consent_token)
      end

      class CallbackError < StandardError
        attr_accessor :error, :error_reason, :error_uri

        def initialize(error, error_reason=nil)
          self.error = error
          self.error_reason = error_reason
        end
      end
    end
  end
end
