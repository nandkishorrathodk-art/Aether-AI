/**
 * AudioProcessor.cpp
 * Implementation of real-time audio processing
 */

#include "audio/AudioProcessor.hpp"
#include <cstring>
#include <numbers>
#include <immintrin.h>  // AVX/AVX2/AVX-512

namespace aether {
namespace audio {

constexpr float PI = std::numbers::pi_v<float>;

AudioProcessor::AudioProcessor(const AudioFormat& format)
    : format_(format)
{
    // Pre-compute Hann window for FFT
    size_t fft_size = 2048;
    fft_window_.resize(fft_size);
    for (size_t i = 0; i < fft_size; ++i) {
        fft_window_[i] = 0.5f * (1.0f - std::cos(2.0f * PI * i / fft_size));
    }
}

void AudioProcessor::process(AudioBuffer& buffer) {
    if (buffer.empty()) return;
    
    // Apply processing chain
    reduceNoise(buffer, 0.01f);
    normalizeVolume(buffer, 0.7f);
}

void AudioProcessor::reduceNoise(AudioBuffer& buffer, float noise_threshold) {
    // Spectral subtraction noise reduction
    
    // 1. Apply window
    applyWindow(buffer);
    
    // 2. FFT
    std::vector<std::complex<float>> spectrum(buffer.size());
    fastFFT(buffer, spectrum);
    
    // 3. Estimate noise floor
    std::vector<float> magnitude(spectrum.size());
    std::transform(spectrum.begin(), spectrum.end(), magnitude.begin(),
        [](const std::complex<float>& c) { return std::abs(c); });
    
    // 4. Subtract noise floor
    float noise_floor = *std::min_element(magnitude.begin(), magnitude.end());
    
    for (size_t i = 0; i < spectrum.size(); ++i) {
        float mag = magnitude[i];
        if (mag < noise_threshold) {
            spectrum[i] = 0.0f;
        } else {
            float scale = (mag - noise_floor) / mag;
            spectrum[i] *= scale;
        }
    }
    
    // 5. IFFT
    fastIFFT(spectrum, buffer);
}

void AudioProcessor::normalizeVolume(AudioBuffer& buffer, float target_level) {
    float peak = getPeakAmplitude(buffer);
    if (peak < 1e-6f) return;  // Avoid division by zero
    
    float gain = target_level / peak;
    
    // SIMD-optimized scaling
    #ifdef __AVX2__
    // AVX2 path - process 8 floats at once
    size_t simd_size = buffer.size() & ~7;  // Round down to multiple of 8
    __m256 gain_vec = _mm256_set1_ps(gain);
    
    for (size_t i = 0; i < simd_size; i += 8) {
        __m256 data = _mm256_loadu_ps(&buffer[i]);
        data = _mm256_mul_ps(data, gain_vec);
        _mm256_storeu_ps(&buffer[i], data);
    }
    
    // Process remaining elements
    for (size_t i = simd_size; i < buffer.size(); ++i) {
        buffer[i] *= gain;
    }
    #else
    // Scalar fallback
    for (float& sample : buffer) {
        sample *= gain;
    }
    #endif
}

void AudioProcessor::cancelEcho(AudioBuffer& buffer, const AudioBuffer& reference) {
    // Adaptive echo cancellation using LMS algorithm
    // Simplified implementation
    
    if (buffer.size() != reference.size()) return;
    
    const float mu = 0.01f;  // Step size
    std::vector<float> filter(64, 0.0f);  // Echo filter
    
    for (size_t i = filter.size(); i < buffer.size(); ++i) {
        // Estimate echo
        float echo = 0.0f;
        for (size_t j = 0; j < filter.size(); ++j) {
            echo += filter[j] * reference[i - j];
        }
        
        // Error signal
        float error = buffer[i] - echo;
        buffer[i] = error;
        
        // Update filter
        for (size_t j = 0; j < filter.size(); ++j) {
            filter[j] += mu * error * reference[i - j];
        }
    }
}

std::vector<float> AudioProcessor::getFrequencySpectrum(const AudioBuffer& buffer) {
    std::vector<std::complex<float>> spectrum(buffer.size());
    fastFFT(buffer, spectrum);
    
    // Return magnitude spectrum
    std::vector<float> magnitude(spectrum.size() / 2);
    for (size_t i = 0; i < magnitude.size(); ++i) {
        magnitude[i] = std::abs(spectrum[i]);
    }
    
    return magnitude;
}

void AudioProcessor::applyEqualizer(AudioBuffer& buffer, const std::vector<float>& gains) {
    // Parametric equalizer using FFT
    std::vector<std::complex<float>> spectrum(buffer.size());
    fastFFT(buffer, spectrum);
    
    // Apply gains to frequency bins
    size_t bins_per_band = spectrum.size() / (gains.size() * 2);
    for (size_t i = 0; i < spectrum.size() / 2; ++i) {
        size_t band = i / bins_per_band;
        if (band < gains.size()) {
            spectrum[i] *= gains[band];
            spectrum[spectrum.size() - 1 - i] *= gains[band];  // Mirror for real signal
        }
    }
    
    fastIFFT(spectrum, buffer);
}

void AudioProcessor::applyWindow(AudioBuffer& buffer) {
    size_t window_size = std::min(buffer.size(), fft_window_.size());
    for (size_t i = 0; i < window_size; ++i) {
        buffer[i] *= fft_window_[i];
    }
}

void AudioProcessor::fastFFT(
    const AudioBuffer& input,
    std::vector<std::complex<float>>& output
) {
    // Simplified FFT - in production, use FFTW or similar
    // This is a placeholder for demonstration
    
    output.resize(input.size());
    for (size_t k = 0; k < output.size(); ++k) {
        std::complex<float> sum(0.0f, 0.0f);
        for (size_t n = 0; n < input.size(); ++n) {
            float angle = 2.0f * PI * k * n / input.size();
            sum += input[n] * std::complex<float>(std::cos(angle), -std::sin(angle));
        }
        output[k] = sum;
    }
}

void AudioProcessor::fastIFFT(
    const std::vector<std::complex<float>>& input,
    AudioBuffer& output
) {
    // Simplified IFFT
    output.resize(input.size());
    for (size_t n = 0; n < output.size(); ++n) {
        std::complex<float> sum(0.0f, 0.0f);
        for (size_t k = 0; k < input.size(); ++k) {
            float angle = 2.0f * PI * k * n / input.size();
            sum += input[k] * std::complex<float>(std::cos(angle), std::sin(angle));
        }
        output[n] = sum.real() / input.size();
    }
}

// StreamProcessor implementation

StreamProcessor::StreamProcessor(size_t chunk_size)
    : chunk_size_(chunk_size)
    , input_buffer_(chunk_size)
{}

AudioBufferPtr StreamProcessor::processChunk(const float* data, size_t size) {
    // Copy to input buffer
    std::copy(data, data + size, input_buffer_.begin());
    
    // Process
    processor_.process(input_buffer_);
    
    // Create output buffer
    auto output = std::make_shared<AudioBuffer>(input_buffer_);
    
    // Call callback if set
    if (callback_) {
        callback_(output);
    }
    
    return output;
}

void StreamProcessor::setProcessCallback(ProcessCallback callback) {
    callback_ = std::move(callback);
}

} // namespace audio
} // namespace aether
