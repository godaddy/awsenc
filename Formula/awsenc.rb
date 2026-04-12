class Awsenc < Formula
  desc "Hardware-backed AWS credential manager using Secure Enclave / TPM"
  homepage "https://github.com/jgowdy/awsenc"
  version "0.1.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/jgowdy/awsenc/releases/download/v0.1.0/awsenc-aarch64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER_ARM64_SHA256"
    else
      url "https://github.com/jgowdy/awsenc/releases/download/v0.1.0/awsenc-x86_64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER_X86_64_SHA256"
    end
  end

  def install
    bin.install "awsenc"
  end

  def caveats
    <<~EOS
      To configure awsenc with the AWS CLI:

        awsenc install --profile <name> \\
          --organization <org>.okta.com \\
          --application <app-url> \\
          --role <role-arn>

      To add shell integration (export detection + awsenc-use):

        # bash: add to ~/.bashrc
        eval "$(awsenc shell-init bash)"

        # zsh: add to ~/.zshrc
        eval "$(awsenc shell-init zsh)"

        # fish: add to ~/.config/fish/config.fish
        awsenc shell-init fish | source
    EOS
  end

  test do
    assert_match "awsenc", shell_output("#{bin}/awsenc --help")
  end
end
