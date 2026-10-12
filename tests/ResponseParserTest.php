<?php

namespace LwbDomaineCd\Tests;

use LwbDomaineCd\ResponseParser;
use PHPUnit\Framework\TestCase;

final class ResponseParserTest extends TestCase
{
    private static function fixture(string $name): string
    {
        return (string) file_get_contents(__DIR__ . '/fixtures/' . $name);
    }

    public function testRegisteredDomainIsNeverAvailable(): void
    {
        $r = (new ResponseParser())->parse('ispbunia.ac.cd', self::fixture('taken-ispbunia-ac-cd.txt'));
        $this->assertSame(ResponseParser::REGISTERED, $r['status']);
    }

    public function testRegisteredDetectionIsCaseInsensitiveOnTheDomain(): void
    {
        $r = (new ResponseParser())->parse('ISPBUNIA.AC.CD', self::fixture('taken-ispbunia-ac-cd.txt'));
        $this->assertSame(ResponseParser::REGISTERED, $r['status']);
    }

    public function testNicReservedNameIsReserved(): void
    {
        $r = (new ResponseParser())->parse('gouv.cd', self::fixture('reserved-gouv-cd.txt'));
        $this->assertSame(ResponseParser::RESERVED, $r['status']);
    }

    public function testServerHoldIsNotAvailable(): void
    {
        $raw = "Domain Name: hold.cd\nDomain Status: serverHold https://icann.org/epp#serverHold\n";
        $this->assertSame(ResponseParser::RESERVED, (new ResponseParser())->parse('hold.cd', $raw)['status']);
    }

    public function testFreeCdDomainIsAvailable(): void
    {
        $r = (new ResponseParser())->parse('zzqtest1791804676.cd', self::fixture('free-cd.txt'));
        $this->assertSame(ResponseParser::AVAILABLE, $r['status']);
    }

    public function testFreeAcCdDomainIsAvailable(): void
    {
        $r = (new ResponseParser())->parse('zzqtest1791804676.ac.cd', self::fixture('free-ac-cd.txt'));
        $this->assertSame(ResponseParser::AVAILABLE, $r['status']);
    }

    public function testEmptyResponseIsUnknown(): void
    {
        $parser = new ResponseParser();
        $this->assertSame(ResponseParser::UNKNOWN, $parser->parse('abc.cd', '')['status']);
        $this->assertSame(ResponseParser::UNKNOWN, $parser->parse('abc.cd', "  \r\n ")['status']);
    }

    public function testRateLimitMessageIsUnknown(): void
    {
        $r = (new ResponseParser())->parse('abc.cd', self::fixture('rate-limit.txt'));
        $this->assertSame(ResponseParser::UNKNOWN, $r['status']);
    }

    public function testUnrecognisedResponseIsUnknown(): void
    {
        $this->assertSame(ResponseParser::UNKNOWN, (new ResponseParser())->parse('abc.cd', "Service temporairement indisponible\n")['status']);
    }

    public function testResponseAboutAnotherDomainIsUnknown(): void
    {
        $r = (new ResponseParser())->parse('autre.cd', self::fixture('free-cd.txt'));
        $this->assertSame(ResponseParser::UNKNOWN, $r['status']);
    }

    public function testFreePhraseInTermsOfUseIsIgnored(): void
    {
        $raw = "Domain Name: abc.cd\n>>> Last update of WHOIS database: 2026-10-12 <<<\nTERMS OF USE: data not found here is available on request\n";
        // Seule la ligne « Domain Name » reste : le domaine est considéré comme pris, jamais libre.
        $this->assertSame(ResponseParser::REGISTERED, (new ResponseParser())->parse('abc.cd', $raw)['status']);
    }

    public function testConfiguredFreePhrasesAreUsed(): void
    {
        $parser = new ResponseParser(['Pas de correspondance'], ResponseParser::DEFAULT_RESERVED_PHRASES);
        $this->assertSame(ResponseParser::AVAILABLE, $parser->parse('abc.cd', "Pas de correspondance pour abc.cd\n")['status']);
        $this->assertSame(ResponseParser::UNKNOWN, $parser->parse('abc.cd', "No match for abc.cd\n")['status']);
    }

    public function testPhrasesFromTextFallsBackToDefaults(): void
    {
        $this->assertSame(['a', 'b'], ResponseParser::phrasesFromText("a\r\n\nb\n", ['x']));
        $this->assertSame(['x'], ResponseParser::phrasesFromText("  \n", ['x']));
    }
}
