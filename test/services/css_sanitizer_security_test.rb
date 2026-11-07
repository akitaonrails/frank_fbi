require "test_helper"

# Guards GHSA-pq4g-8rxf-4g29 / CVE-2026-116695 in the crass CSS tokenizer.
#
# Crass used to consume a bad URL past a `)` that followed an escaped
# backslash, so CSS sanitizers built on it (Loofah, rails-html-sanitizer)
# re-emitted declarations a browser would then apply. The app sanitizes
# attacker-controlled email HTML, and the reports render that content, so the
# scrub path must keep stripping smuggled declarations.
class CssSanitizerSecurityTest < ActiveSupport::TestCase
  # A bad URL token is easier to build from a plain backslash character than
  # from string escapes, where the count is easy to misread.
  BACKSLASH = 92.chr

  # Payloads from the crass advisory regression suite: a bad URL is opened
  # inside an allowlisted function, then the escaped backslash is followed by
  # `)` and the declaration the sanitizer normally removes.
  SMUGGLING_PAYLOADS = [
    'width:calc(url(x"' + BACKSLASH * 2 + ")); position:fixed; x:)",
    'color:[url(x"' + BACKSLASH * 2 + ")]; position:fixed"
  ].freeze

  test "crass is at a version patched for the bad URL tokenization bypass" do
    assert_operator Gem.loaded_specs.fetch("crass").version, :>=, Gem::Version.new("1.0.8")
  end

  test "loofah strips declarations smuggled through a bad URL after an escaped backslash" do
    SMUGGLING_PAYLOADS.each do |css|
      scrubbed = Loofah::HTML5::Scrub.scrub_css(css)

      assert_no_match(/position\s*:\s*fixed/i, scrubbed, "position:fixed survived scrubbing of #{css.inspect}")
      assert_no_match(/x:\s*\)/i, scrubbed, "trailing smuggled junk survived scrubbing of #{css.inspect}")
    end
  end

  test "loofah keeps legitimate declarations while scrubbing the bypass payload" do
    scrubbed = Loofah::HTML5::Scrub.scrub_css('width:calc(url(x"' + BACKSLASH * 2 + ")); position:fixed; color:red")

    assert_match(/color\s*:\s*red/i, scrubbed, "the sanitizer must not become a blanket deny")
  end
end
