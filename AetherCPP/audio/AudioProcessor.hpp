/**
 * AudioProcessor.hpp
 * Real-time audio processing with <10ms latency
 * 
 * Optimized for:
 * - Intel/AMD: AVX-512, AVX2
 * - Apple Silicon: NEON
 * - Multi-threading with std::execution
 */

#pragma once

#include <vector>
#include <complex>
#include <memory>
#include <cmath>
#include <algorithm>
#include <execution>

namespace aether {
namespace audio {

// Audio format
struct AudioFormat {
    uint32_t sample_rate = 48000;  // 48kHz
    uint16_t channels = 2;          // Stereo
    uint16_t bits_per_sample = 16;  // 16-bit PCM
};

// Audio buffer
using AudioBuffer = std::vector<float>;
using AudioBufferPtr = std::shared_ptr<AudioBuffer>;

/**
 * High-performance audio processor
 * 
 * Features:
 * - Real-time processing (<10ms latency)
 * - SIMD optimization (AVX2/AVX-512/NEON)
 * - Multi-threaded
 * - Zero-copy where possible
 */
class AudioProcessor {
public:
    explicit AudioProcessor(const AudioFormat& format = AudioFormat());
    ~AudioProcessor() = default;

    // Process audio buffer in-place
    void process(AudioBuffer& buffer);
    
    // Voice Activity Detection (VAD)
    bool detectVoiceActivity(const AudioBuffer& buffer, float threshold = 0.02f);
    
    // Noise reduction
    void reduceNoise(AudioBuffer& buffer, float noise_threshold = 0.01f);
    
    // Volume normalization
    void normalizeVolume(AudioBuffer& buffer, float target_level = 0.7f);
    
    // Echo cancellation
    void cancelEcho(AudioBuffer& buffer, const AudioBuffer& reference);
    
    // Frequency analysis (FFT)
    std::vector<float> getFrequencySpectrum(const AudioBuffer& buffer);
    
    // Apply equalizer
    void applyEqualizer(AudioBuffer& buffer, const std::vector<float>& gains);
    
    // Get RMS energy
    float getRMSEnergy(const AudioBuffer& buffer) const;
    
    // Get peak amplitude
    float getPeakAmplitude(const AudioBuffer& buffer) const;
    
private:
    AudioFormat format_;
    std::vector<float> noise_profile_;
    std::vector<float> fft_window_;
    
    // SIMD-optimized helper functions
    void applyWindow(AudioBuffer& buffer);
    void fastFFT(const AudioBuffer& input, std::vector<std::complex<float>>& output);
    void fastIFFT(const std::vector<std::complex<float>>& input, AudioBuffer& output);
};

/**
 * Real-time audio stream processor
 * Processes audio in chunks for minimal latency
 */
class StreamProcessor {
public:
    StreamProcessor(size_t chunk_size = 1024);
    
    // Process incoming audio chunk
    AudioBufferPtr processChunk(const float* data, size_t size);
    
    // Set callback for processed audio
    using ProcessCallback = std::function<void(const AudioBufferPtr&)>;
    void setProcessCallback(ProcessCallback callback);
    
private:
    AudioProcessor processor_;
    size_t chunk_size_;
    ProcessCallback callback_;
    AudioBuffer input_buffer_;
};

// Inline implementations for performance-critical functions

inline float AudioProcessor::getRMSEnergy(const AudioBuffer& buffer) const {
    if (buffer.empty()) return 0.0f;
    
    // SIMD-optimized sum of squares
    float sum_sq = std::transform_reduce(
        std::execution::par_unseq,
        buffer.begin(), buffer.end(),
        0.0f,
        std::plus<>(),
        [](float x) { return x * x; }
    );
    
    return std::sqrt(sum_sq / buffer.size());
}

inline float AudioProcessor::getPeakAmplitude(const AudioBuffer& buffer) const {
    if (buffer.empty()) return 0.0f;
    
    // SIMD-optimized max absolute value
    return std::transform_reduce(
        std::execution::par_unseq,
        buffer.begin(), buffer.end(),
        0.0f,
        [](float a, float b) { return std::max(a, b); },
        [](float x) { return std::abs(x); }
    );
}

inline bool AudioProcessor::detectVoiceActivity(
    const AudioBuffer& buffer, 
    float threshold
) {
    return getRMSEnergy(buffer) > threshold;
}

} // namespace audio
} // namespace aether
