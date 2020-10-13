// Copyright 2017 Google Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

#include <gtest/gtest.h>

#include "packager/base/bind.h"
#include "packager/media/base/stream_info.h"
#include "packager/media/base/text_sample.h"
#include "packager/media/formats/webvtt/webvtt_parser.h"

namespace shaka {
namespace media {
namespace {

const uint32_t kStreamId = 0;
const uint32_t kTimeScale = 1000;

const char* kNoId = "";
const char* kNoSettings = "";

std::string ToString(const std::vector<uint8_t>& v) {
  return std::string(v.begin(), v.end());
}

}  // namespace

class WebVttParserTest : public testing::Test {
 protected:
  void SetUpAndInitialize() {
    parser_ = std::make_shared<WebVttParser>();
    parser_->Init(
        base::Bind(&WebVttParserTest::InitCB, base::Unretained(this)),
        base::Bind(&WebVttParserTest::NewMediaSampleCB, base::Unretained(this)),
        base::Bind(&WebVttParserTest::NewTextSampleCB, base::Unretained(this)),
        nullptr);
  }

  void InitCB(const std::vector<std::shared_ptr<StreamInfo>>& streams) {
    streams_ = streams;
  }

  bool NewMediaSampleCB(uint32_t stream_id,
                        std::shared_ptr<MediaSample> sample) {
    ADD_FAILURE() << "Should not get media samples";
    return false;
  }

  bool NewTextSampleCB(uint32_t stream_id, std::shared_ptr<TextSample> sample) {
    EXPECT_EQ(stream_id, kStreamId);
    samples_.emplace_back(std::move(sample));
    return true;
  }

  std::shared_ptr<WebVttParser> parser_;
  std::vector<std::shared_ptr<StreamInfo>> streams_;
  std::vector<std::shared_ptr<TextSample>> samples_;
};

TEST_F(WebVttParserTest, FailToParseEmptyFile) {
  const uint8_t text[] = "";

  ASSERT_NO_FATAL_FAILURE(SetUpAndInitialize());

  ASSERT_TRUE(parser_->Parse(text, sizeof(text) - 1));
  ASSERT_TRUE(parser_->Flush());

  ASSERT_TRUE(streams_.empty());
  ASSERT_TRUE(samples_.empty());
}

TEST_F(WebVttParserTest, ParseOnlyHeader) {
  const uint8_t text[] =
      "WEBVTT\n"
      "\n";

  ASSERT_NO_FATAL_FAILURE(SetUpAndInitialize());

  ASSERT_TRUE(parser_->Parse(text, sizeof(text) - 1));
  ASSERT_TRUE(parser_->Flush());

  ASSERT_TRUE(streams_.empty());
  ASSERT_TRUE(samples_.empty());
}

TEST_F(WebVttParserTest, ParseHeaderWithBOM) {
  const uint8_t text[] =
      "\xEF\xBB\xBFWEBVTT\n"
      "\n";

  ASSERT_NO_FATAL_FAILURE(SetUpAndInitialize());

  ASSERT_TRUE(parser_->Parse(text, sizeof(text) - 1));
  ASSERT_TRUE(parser_->Flush());

  ASSERT_TRUE(streams_.empty());
  ASSERT_TRUE(samples_.empty());
}

TEST_F(WebVttParserTest, FailToParseHeaderWrongWord) {
  const uint8_t text[] =
      "NOT WEBVTT\n"
      "\n";

  ASSERT_NO_FATAL_FAILURE(SetUpAndInitialize());

  ASSERT_FALSE(parser_->Parse(text, sizeof(text) - 1));

  ASSERT_TRUE(streams_.empty());
  ASSERT_TRUE(samples_.empty());
}

TEST_F(WebVttParserTest, FailToParseHeaderNotOneLine) {
  const uint8_t text[] =
      "WEBVTT\n"
      "WEBVTT\n"
      "\n";

  ASSERT_NO_FATAL_FAILURE(SetUpAndInitialize());

  ASSERT_FALSE(parser_->Parse(text, sizeof(text) - 1));

  ASSERT_TRUE(streams_.empty());
  ASSERT_TRUE(samples_.empty());
}

TEST_F(WebVttParserTest, SendsStreamInfo) {
  const uint8_t text[] =
      "WEBVTT\n"
      "\n"
      "00:00:00.000 --> 00:01:00.000\n"
      "Testing\n";

  ASSERT_NO_FATAL_FAILURE(SetUpAndInitialize());

  ASSERT_TRUE(parser_->Parse(text, sizeof(text) - 1));
  ASSERT_TRUE(parser_->Flush());

  ASSERT_EQ(streams_.size(), 1u);
  EXPECT_EQ(streams_[0]->time_scale(), kTimeScale);
  EXPECT_EQ(streams_[0]->is_encrypted(), false);
  EXPECT_EQ(streams_[0]->codec(), kCodecWebVtt);
  EXPECT_EQ(streams_[0]->codec_string(), "wvtt");
}

TEST_F(WebVttParserTest, IgnoresZeroDurationCues) {
  const uint8_t text[] =
      "WEBVTT\n"
      "\n"
      "00:01:00.000 --> 00:01:00.000\n"
      "This subtitle would never show\n";

  ASSERT_NO_FATAL_FAILURE(SetUpAndInitialize());

  ASSERT_TRUE(parser_->Parse(text, sizeof(text) - 1));
  ASSERT_TRUE(parser_->Flush());

  ASSERT_EQ(streams_.size(), 1u);
  ASSERT_TRUE(samples_.empty());
}

TEST_F(WebVttParserTest, ParseOneCue) {
  const uint8_t text[] =
      "WEBVTT\n"
      "\n"
      "00:01:00.000 --> 01:00:00.000\n"
      "subtitle\n";

  ASSERT_NO_FATAL_FAILURE(SetUpAndInitialize());

  ASSERT_TRUE(parser_->Parse(text, sizeof(text) - 1));
  ASSERT_TRUE(parser_->Flush());

  ASSERT_EQ(streams_.size(), 1u);
  ASSERT_EQ(samples_.size(), 1u);
  EXPECT_EQ(samples_[0]->id(), kNoId);
  EXPECT_EQ(samples_[0]->start_time(), 60000u);
  EXPECT_EQ(samples_[0]->duration(), 3540000u);
  EXPECT_EQ(samples_[0]->settings(), kNoSettings);
  EXPECT_EQ(samples_[0]->payload(), "subtitle");
}

TEST_F(WebVttParserTest, ParseOneCueWithStyleAndRegion) {
  const uint8_t text[] =
      "WEBVTT\n"
      "\n"
      "STYLE\n"
      "::cue { color:lime }\n"
      "\n"
      "REGION\n"
      "id:scroll\n"
      "scrol:up\n"
      "\n"
      "00:01:00.000 --> 01:00:00.000\n"
      "subtitle\n";

  ASSERT_NO_FATAL_FAILURE(SetUpAndInitialize());

  ASSERT_TRUE(parser_->Parse(text, sizeof(text) - 1));
  ASSERT_TRUE(parser_->Flush());

  ASSERT_EQ(streams_.size(), 1u);
  ASSERT_EQ(samples_.size(), 1u);

  EXPECT_EQ(ToString(streams_[0]->codec_config()),
            "STYLE\n"
            "::cue { color:lime }\n"
            "\n"
            "REGION\n"
            "id:scroll\n"
            "scrol:up");
  EXPECT_EQ(samples_[0]->id(), kNoId);
  EXPECT_EQ(samples_[0]->start_time(), 60000u);
  EXPECT_EQ(samples_[0]->duration(), 3540000u);
  EXPECT_EQ(samples_[0]->settings(), kNoSettings);
  EXPECT_EQ(samples_[0]->payload(), "subtitle");
}

TEST_F(WebVttParserTest, ParseOneEmptyCue) {
  const uint8_t text[] =
      "WEBVTT\n"
      "\n"
      "00:01:00.000 --> 01:00:00.000\n"
      "\n";

  ASSERT_NO_FATAL_FAILURE(SetUpAndInitialize());

  ASSERT_TRUE(parser_->Parse(text, sizeof(text) - 1));
  ASSERT_TRUE(parser_->Flush());

  ASSERT_EQ(streams_.size(), 1u);
  ASSERT_EQ(samples_.size(), 1u);
  EXPECT_EQ(samples_[0]->payload(), "");
}

TEST_F(WebVttParserTest, FailToParseCueWithArrowInId) {
  const uint8_t text[] =
      "WEBVTT\n"
      "\n"
      "-->\n"
      "00:01:00.000 --> 01:00:00.000\n"
      "subtitle\n";

  ASSERT_NO_FATAL_FAILURE(SetUpAndInitialize());

  ASSERT_TRUE(parser_->Parse(text, sizeof(text) - 1));
  ASSERT_FALSE(parser_->Flush());
}

TEST_F(WebVttParserTest, ParseOneCueWithId) {
  const uint8_t text[] =
      "WEBVTT\n"
      "\n"
      "id\n"
      "00:01:00.000 --> 01:00:00.000\n"
      "subtitle\n";

  ASSERT_NO_FATAL_FAILURE(SetUpAndInitialize());

  ASSERT_TRUE(parser_->Parse(text, sizeof(text) - 1));
  ASSERT_TRUE(parser_->Flush());

  ASSERT_EQ(streams_.size(), 1u);
  ASSERT_EQ(samples_.size(), 1u);
  EXPECT_EQ(samples_[0]->id(), "id");
  EXPECT_EQ(samples_[0]->payload(), "subtitle");
}

TEST_F(WebVttParserTest, ParseOneEmptyCueWithId) {
  const uint8_t text[] =
      "WEBVTT\n"
      "\n"
      "id\n"
      "00:01:00.000 --> 01:00:00.000\n"
      "\n";

  ASSERT_NO_FATAL_FAILURE(SetUpAndInitialize());

  ASSERT_TRUE(parser_->Parse(text, sizeof(text) - 1));
  ASSERT_TRUE(parser_->Flush());

  ASSERT_EQ(streams_.size(), 1u);
  ASSERT_EQ(samples_.size(), 1u);
  EXPECT_EQ(samples_[0]->id(), "id");
  EXPECT_EQ(samples_[0]->payload(), "");
}

TEST_F(WebVttParserTest, ParseOneCueWithSettings) {
  const uint8_t text[] =
      "WEBVTT\n"
      "\n"
      "00:01:00.000 --> 01:00:00.000 size:50%\n"
      "subtitle\n";

  ASSERT_NO_FATAL_FAILURE(SetUpAndInitialize());

  ASSERT_TRUE(parser_->Parse(text, sizeof(text) - 1));
  ASSERT_TRUE(parser_->Flush());

  ASSERT_EQ(streams_.size(), 1u);
  ASSERT_EQ(samples_.size(), 1u);
  EXPECT_EQ(samples_[0]->settings(), "size:50%");
}

// Verify that a typical case with mulitple cues work.
TEST_F(WebVttParserTest, ParseMultipleCues) {
  const uint8_t text[] =
      "WEBVTT\n"
      "\n"
      "00:00:01.000 --> 00:00:05.200\n"
      "subtitle A\n"
      "\n"
      "00:00:02.321 --> 00:00:07.000\n"
      "subtitle B\n"
      "\n"
      "00:00:05.800 --> 00:00:08.000\n"
      "subtitle C\n";

  ASSERT_NO_FATAL_FAILURE(SetUpAndInitialize());

  ASSERT_TRUE(parser_->Parse(text, sizeof(text) - 1));
  ASSERT_TRUE(parser_->Flush());

  ASSERT_EQ(streams_.size(), 1u);
  ASSERT_EQ(samples_.size(), 3u);

  EXPECT_EQ(samples_[0]->start_time(), 1000u);
  EXPECT_EQ(samples_[0]->duration(), 4200u);
  EXPECT_EQ(samples_[0]->payload(), "subtitle A");
  EXPECT_EQ(samples_[1]->start_time(), 2321u);
  EXPECT_EQ(samples_[1]->duration(), 4679u);
  EXPECT_EQ(samples_[1]->payload(), "subtitle B");
  EXPECT_EQ(samples_[2]->start_time(), 5800u);
  EXPECT_EQ(samples_[2]->duration(), 2200u);
  EXPECT_EQ(samples_[2]->payload(), "subtitle C");
}

// Verify that a typical case with mulitple cues work even when comments are
// present.
TEST_F(WebVttParserTest, ParseWithComments) {
  const uint8_t text[] =
      "WEBVTT\n"
      "\n"
      "NOTE This is a one line comment\n"
      "\n"
      "00:00:01.000 --> 00:00:05.200\n"
      "subtitle A\n"
      "\n"
      "NOTE\n"
      "This is a multi-line comment\n"
      "\n"
      "00:00:02.321 --> 00:00:07.000\n"
      "subtitle B\n"
      "\n"
      "NOTE This is a single line comment that\n"
      "spans two lines\n"
      "\n"
      "NOTE\tThis is a comment that using a tab\n"
      "\n"
      "00:00:05.800 --> 00:00:08.000\n"
      "subtitle C\n";

  ASSERT_NO_FATAL_FAILURE(SetUpAndInitialize());

  ASSERT_TRUE(parser_->Parse(text, sizeof(text) - 1));
  ASSERT_TRUE(parser_->Flush());

  ASSERT_EQ(streams_.size(), 1u);
  ASSERT_EQ(samples_.size(), 3u);

  EXPECT_EQ(samples_[0]->payload(), "subtitle A");
  EXPECT_EQ(samples_[1]->payload(), "subtitle B");
  EXPECT_EQ(samples_[2]->payload(), "subtitle C");
}
}  // namespace media
}  // namespace shaka
