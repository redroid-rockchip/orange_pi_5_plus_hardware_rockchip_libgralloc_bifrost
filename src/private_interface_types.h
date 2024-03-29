/*
 * Copyright (C) 2017, 2020, 2022 Arm Limited. All rights reserved.
 *
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#define GRALLOC_ARM_BUFFER_ATTR_DATASPACE_SUPPORT

#include <assert.h>

enum
{
	/* CROP_RECT is intended to be
	 * written by producers and read by consumers.
	 * A producer should write these parameters before
	 * it queues a buffer to the consumer.
	 */

	/* CROP RECT, defined as an int array of top, left, height, width. Origin in top-left corner */
	GRALLOC_ARM_BUFFER_ATTR_CROP_RECT = 1,

	/* Dataspace - used for YUV to RGB conversion. */
	GRALLOC_ARM_BUFFER_ATTR_DATASPACE = 2,

	GRALLOC_ARM_BUFFER_ATTR_LAST
};

typedef uint32_t buf_attr;

/*
 * Deprecated.
 * Use GRALLOC_ARM_BUFFER_ATTR_DATASPACE
 * instead.
 */
typedef enum
{
	MALI_YUV_NO_INFO,
	MALI_YUV_BT601_NARROW,
	MALI_YUV_BT601_WIDE,
	MALI_YUV_BT709_NARROW,
	MALI_YUV_BT709_WIDE
} mali_gralloc_yuv_info;
