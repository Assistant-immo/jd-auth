require_relative '../../spec_helper'

describe JdAuth::ApplicationHelper do

  before do
    class DummyController < ActionController::Base

    end
  end

  let(:dummy_controller) {DummyController.new}

  describe :jd_auth_authenticate do
    before do
      allow(dummy_controller).to receive(:render)
    end
    context "No token in headers" do
      before do
        dummy_controller.request = OpenStruct.new(headers: {})
      end
      it "should call validate with nil" do
        expect(JdAuth::Token).to receive(:validate).with(nil)
        dummy_controller.jd_auth_authenticate
      end
    end

    context "Token wrong format in headers" do
      before do
        dummy_controller.request = OpenStruct.new(headers: {"Authorization" => "Tken abcd"})
      end
      it "should call validate with nil" do
        expect(JdAuth::Token).to receive(:validate).with(nil)
        dummy_controller.jd_auth_authenticate
      end
    end

    context "Token correct format in headers" do
      before do
        dummy_controller.request = OpenStruct.new(headers: {"Authorization" => "Token abcd"})
      end
      it "should call validate with nil" do
        expect(JdAuth::Token).to receive(:validate).with("abcd")
        dummy_controller.jd_auth_authenticate
      end

      context "validate raise no_token" do
        it "should return false and render error" do
          expect(JdAuth::Token).to receive(:validate).with("abcd").and_raise(JdAuth::Errors::NoTokenError)
          expect(dummy_controller).to receive(:render).with({
                                                                json: {
                                                                    message: 'Invalid authentication',
                                                                    code: "please_request_new_token"
                                                                },
                                                                status: 401
                                                            })
          expect(dummy_controller.jd_auth_authenticate).to eq(false)
        end
      end

      context "validate raise invalid_token" do
        it "should return false and render error" do
          expect(JdAuth::Token).to receive(:validate).with("abcd").and_raise(JdAuth::Errors::InvalidTokenError)
          expect(dummy_controller).to receive(:render).with({
                                                                json: {
                                                                    message: 'Invalid authentication',
                                                                    code: "please_request_new_token"
                                                                },
                                                                status: 401
                                                            })
          expect(dummy_controller.jd_auth_authenticate).to eq(false)
        end
      end

      context "validate raise expired_token" do
        it "should return false and render error" do
          expect(JdAuth::Token).to receive(:validate).with("abcd").and_raise(JdAuth::Errors::ExpiredTokenError)
          expect(dummy_controller).to receive(:render).with({
                                                                json: {
                                                                    message: 'Invalid authentication',
                                                                    code: "please_request_new_token"
                                                                },
                                                                status: 401
                                                            })
          expect(dummy_controller.jd_auth_authenticate).to eq(false)
        end
      end

      context "validate ok, role nil" do
        it "should return false and render error" do
          expect(JdAuth::Token).to receive(:validate).with("abcd").and_return({

                                                                              })
          expect(dummy_controller).to receive(:render).with({
                                                                json: {
                                                                    message: 'Forbidden'
                                                                },
                                                                status: 403
                                                            })
          expect(dummy_controller.jd_auth_authenticate).to eq(false)
        end
      end

      context "validate ok, role not nil" do
        it "should return false and render error" do
          res = double("response")
          expect(res).to receive(:set_header).with("Authorization-Role", "user")
          expect(res).to receive(:set_header).with("Access-Control-Expose-Headers", "Authorization-Role")

          expect(JdAuth::Token).to receive(:validate).with("abcd").and_return({
              role: 'user'
                                                                              })
          expect(dummy_controller).to receive(:response).twice.and_return(res)

          expect(dummy_controller.jd_auth_authenticate).to eq(true)
        end
      end


    end
  end

  describe :jd_auth_current_user do
    it "should return instance variable" do
      dummy_controller.instance_variable_set :@jd_auth_current_user, "jd_auth_current_user"
      expect(dummy_controller.jd_auth_current_user).to eq("jd_auth_current_user")
    end
  end

  describe :jd_auth_only_roles do
    context "Role in included in roles" do
      it "should return true" do
        dummy_controller.instance_variable_set :@jd_auth_current_user, OpenStruct.new({role: "user"})
        expect(dummy_controller.jd_auth_only_roles ["admin", "user"]).to eq(true)
      end
    end

    context "Role not in included in roles" do
      it "should return true" do
        dummy_controller.instance_variable_set :@jd_auth_current_user, OpenStruct.new({role: "user"})
        expect(dummy_controller.jd_auth_only_roles ["admin"]).to eq(false)
      end
    end

  end
end