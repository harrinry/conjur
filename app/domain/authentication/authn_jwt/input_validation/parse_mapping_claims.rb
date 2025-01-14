module Authentication
  module AuthnJwt
    module InputValidation
      # Parse mapping-claims secret value and return a validated mapping hashtable
      ParseMappingClaims ||= CommandClass.new(
        dependencies: {
          validate_claim_name: ValidateClaimName.new(
            deny_claims_list_value: CLAIMS_DENY_LIST
          ),
          logger: Rails.logger
        },
        inputs: %i[mapping_claims]
      ) do
        def call
          @logger.debug(LogMessages::Authentication::AuthnJwt::ParsingMappingClaims.new(@mapping_claims))
          validate_mapping_claims_secret_value_exists
          validate_mapping_claims_value_string
          validate_mapping_claims_list_values
          @logger.debug(LogMessages::Authentication::AuthnJwt::ParsedMappingClaims.new(mapping_hash))
          mapping_hash
        end

        private

        def validate_mapping_claims_secret_value_exists
          raise Errors::Authentication::AuthnJwt::MappingClaimsMissingInput if
            @mapping_claims.blank?
        end

        def validate_mapping_claims_value_string
          validate_last_symbol_is_not_list_delimiter
          validate_array_after_split
        end

        def validate_last_symbol_is_not_list_delimiter
          # split ignores empty values at the end of string
          # ",,ddd,,,,,".split(",") == ["", "", "ddd"]
          raise Errors::Authentication::AuthnJwt::MappingClaimsBlankOrEmpty, @mapping_claims if
            mapping_claims_last_character == CLAIMS_CHARACTER_DELIMITER
        end

        def mapping_claims_last_character
          @mapping_claims_last_character ||= @mapping_claims[-1]
        end

        def validate_array_after_split
          raise Errors::Authentication::AuthnJwt::MappingClaimsBlankOrEmpty, @mapping_claims if
            mapping_tuples_list.empty?
        end

        def mapping_tuples_list
          @mapping_tuples ||= @mapping_claims
            .split(CLAIMS_CHARACTER_DELIMITER)
            .map { |value| value.strip }
        end

        def validate_mapping_claims_list_values
          mapping_tuples_list.each do |tuple|
            raise Errors::Authentication::AuthnJwt::MappingClaimsBlankOrEmpty, @mapping_claims if
              tuple.blank?

            annotation_name, claim_name = mapping_tuple_values(tuple)
            add_to_mapping_hash(annotation_name, claim_name)
          end
        end

        def mapping_tuple_values(tuple)
          values = tuple
            .split(TUPLE_CHARACTER_DELIMITER)
            .map { |value| value.strip }
          raise Errors::Authentication::AuthnJwt::MappingClaimInvalidFormat, tuple unless values.length == 2

          [valid_claim_value(values[0], tuple),
           valid_claim_value(values[1], tuple)]
        end

        def valid_claim_value(value, tuple)
          raise Errors::Authentication::AuthnJwt::MappingClaimInvalidFormat, tuple if value.blank?

          begin
            @validate_claim_name.call(
              claim_name: value
            )
          rescue => e
            raise Errors::Authentication::AuthnJwt::MappingClaimInvalidClaimFormat.new(tuple, e.inspect)
          end
          value
        end

        def add_to_mapping_hash(annotation_name, claim_name)
          raise Errors::Authentication::AuthnJwt::MappingClaimDuplicationError.new('annotation name', annotation_name) unless
            key_set.add?(annotation_name)
          raise Errors::Authentication::AuthnJwt::MappingClaimDuplicationError.new('claim name', claim_name) unless
            value_set.add?(claim_name)

          @logger.debug(LogMessages::Authentication::AuthnJwt::ClaimMapDefinition.new(annotation_name, claim_name))
          mapping_hash[annotation_name] = claim_name
        end

        def key_set
          @key_set ||= Set.new
        end

        def value_set
          @value_set ||= Set.new
        end

        def mapping_hash
          @mapping_hash ||= {}
        end
      end
    end
  end
end
