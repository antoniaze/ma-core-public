/*
    Mango - Open Source M2M - http://mango.serotoninsoftware.com
    Copyright (C) 2006-2011 Serotonin Software Technologies Inc.
    @author Matthew Lohbihler
    
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.serotonin.m2m2.db.dao;

import java.util.List;

import com.serotonin.db.MappedRowCallback;
import com.serotonin.m2m2.rt.dataImage.IdPointValueTime;
import com.serotonin.m2m2.rt.dataImage.PointValueTime;
import com.serotonin.m2m2.rt.dataImage.SetPointSource;
import com.serotonin.m2m2.vo.pair.LongPair;

public interface PointValueDao {
	
    /**
     * Only the PointValueCache should call this method during runtime. Do not use.
     */
    public PointValueTime savePointValueSync(int pointId, PointValueTime pointValue, SetPointSource source);

    /**
     * Only the PointValueCache should call this method during runtime. Do not use.
     */
    public void savePointValueAsync(int pointId, PointValueTime pointValue, SetPointSource source);

    /**
     * Get the point values >= since
     * @param pointId
     * @param since
     * @return
     */
    public List<PointValueTime> getPointValues(int pointId, long since);

    /**
     * Get point values >= from and < to
     * @param pointId
     * @param from
     * @param to
     * @return
     */
    public List<PointValueTime> getPointValuesBetween(int pointId, long from, long to);

    /**
     * Get point values in reverse time order
     * @param pointId
     * @param limit
     * @return
     */
    public List<PointValueTime> getLatestPointValues(int pointId, int limit);

    /**
     * Get point values < before in reverse time order
     * @param pointId
     * @param limit
     * @param before
     * @return
     */
    public List<PointValueTime> getLatestPointValues(int pointId, int limit, long before);

    /**
     * Get the latest point value for this point
     * @param pointId
     * @return null or value
     */
    public PointValueTime getLatestPointValue(int pointId);

    /**
     * Get the first point value < time
     * @param pointId
     * @param time
     * @return null or value
     */
    public PointValueTime getPointValueBefore(int pointId, long time);

    /**
     * Get the point value at or just after this time
     * @param pointId
     * @param time
     * @return
     */
    public PointValueTime getPointValueAfter(int pointId, long time);

    /**
     * Get the point value (if any) at this time.
     * @param pointId
     * @param time
     * @return null or value
     */
    public PointValueTime getPointValueAt(int pointId, long time);

    /**
     * Get point values >= from and < to
     * @param pointId
     * @param from
     * @param to
     * @return
     */
    public void getPointValuesBetween(int pointId, long from, long to, MappedRowCallback<PointValueTime> callback);

    /**
     * Get point values >= from and < to
     * @param pointId
     * @param from
     * @param to
     * @return ordered list for all values by time
     */
    public void getPointValuesBetween(List<Integer> pointIds, long from, long to,
            MappedRowCallback<IdPointValueTime> callback);

    /**
     * Delete values < time
     * @param pointId
     * @param time
     * @return
     */
    public long deletePointValuesBefore(int pointId, long time);

    /**
     * Delete all values
     * @param pointId
     * @return
     */
    public long deletePointValues(int pointId);

    /**
     * Delete values for all points
     * @return
     */
    public long deleteAllPointData();

    /**
     * Delete any point values that are no longer tied to a point in the Data Points table
     * @return
     */
    public long deleteOrphanedPointValues();

    /**
     * SQL Specific to delete annotations if they are stored elsewhere
     */
    public void deleteOrphanedPointValueAnnotations();

    /**
     * Count the values >= from and < to
     * @param pointId
     * @param from
     * @param to
     * @return
     */
    public long dateRangeCount(int pointId, long from, long to);

    /**
     * Get the earliest timestamp for this point
     * @param pointId
     * @return
     */
    public long getInceptionDate(int pointId);

    /**
     * Return the earliest point value's time for all point IDs
     * @param pointIds
     * @return earliest ts or 0
     */
    public long getStartTime(List<Integer> pointIds);

    /**
     * Return the latest point value's time for all point IDs
     * @param pointIds
     * @return latest time or -1l
     */
    public long getEndTime(List<Integer> pointIds);

    /**
     * Return the latest and earliest point value times for this list of IDs
     * @param pointIds
     * @return null if none exists
     */
    public LongPair getStartAndEndTime(List<Integer> pointIds);

    public List<Long> getFiledataIds(int pointId);

	/**
	 * Delete any point values where data type doesn't match the vo,
	 * just in case the data type was changed.
	 * Only do this if the data type has actually changed because it is
	 * just really slow if the database is big or busy.
	 * 
	 * @param id
	 * @param dataTypeId
	 */
	public long deletePointValuesWithMismatchedType(int id, int dataTypeId);

	/**
	 * Update a given point value at some time by queueing up a work item
	 * 
	 * @param id
	 * @param pvt
	 * @param object
	 */
	public void updatePointValueAsync(int dataPointId, PointValueTime pvt, SetPointSource source);

	/**
	 * Update a given point value at some time directly
	 * @param dataPointId
	 * @param pvt
	 * @param source
	 * @return
	 */
	public PointValueTime updatePointValueSync(int dataPointId, PointValueTime pvt, SetPointSource source);

	/**
	 * Delete all data point values at a time
	 * @param dataPointId
	 * @param ts
	 * @return
	 */
	public long deletePointValue(int dataPointId, long ts);
}
